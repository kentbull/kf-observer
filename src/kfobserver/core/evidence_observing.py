"""Full-evidence observation persistence and authenticated source polling.

This application owns configured-source acquisition.  KERIpy still
owns the shared evidence processors and durable registry stores.
"""
from collections import deque
from dataclasses import asdict, dataclass, field
import logging
import ipaddress
import ssl
from math import isfinite
from pathlib import Path
from urllib.parse import urlsplit

from hio.base import doing
from hio.core import http
from keri import Vrsn_2_0
from keri.acdc import Regery
from keri.core import (BlindState, Blinder, BoundState, Codens, Counter,
                       Kevery, Number, NumDex, Parser, SerderACDC, query)
from keri.core.kraming import Pruner
from keri.db.dbing import snKey
from keri.db.subing import Suber
from keri.kering import (ConfigurationError, KeriError, ValidationError, MissingSignatureError,
    MissingWitnessSignatureError, MissingDelegationError, OutOfOrderError,
    MissingDelegableApprovalError, UnverifiedReceiptError,
    UnverifiedWitnessReceiptError, UnverifiedTransferableReceiptError)
from keri.app.httping import CESR_CONTENT_TYPE
from keri.db import dbing, koming
from keri.help import helping



@dataclass
class Observation:
    """Durable completed-pull time and exact accepted heads for one source URL."""
    completed: str = ''
    heads: dict = field(default_factory=dict)


@dataclass
class ReaderAccount:
    """Durable dynamic reader authorization, separate from protocol evidence."""
    roles: list[str] = field(default_factory=list)


class ObservationBaser(dbing.LMDBer):
    """Caller-owned LMDB persistence for completed source observations."""
    TailDirPath = 'keri/observer'
    AltTailDirPath = '.keri/observer'

    def reopen(self, **kwa):
        """Open source observations and dynamic reader accounts in this owned store."""
        super().reopen(**kwa)
        self.observations = koming.Komer(
            db=self, subkey='observations.', klas=Observation)
        self.accounts = koming.Komer(
            db=self, subkey='accounts.', klas=ReaderAccount)
        return self.opened


@dataclass(frozen=True)
class SourceTrust:
    """Bind one HTTPS registrar URL to an explicit CA and TLS identity.

    DNS URLs use their URL hostname.  An IP URL requires an explicit,
    operator-selected certificate hostname mapping.
    """
    url: str
    cafilepath: str
    certedhost: str | None = None

    @classmethod
    def fromConfig(cls, value):
        """Return a strictly validated full-evidence source trust record."""
        if isinstance(value, cls):
            value = dict(url=value.url, cafilepath=value.cafilepath,
                         certedhost=value.certedhost)
        if not isinstance(value, dict):
            raise ValueError('registrar source must configure url and cafilepath')
        unknown = set(value) - {'url', 'cafilepath', 'certedhost'}
        if unknown:
            raise ValueError(f'unknown registrar source trust fields: {sorted(unknown)}')
        url = value.get('url')
        cafilepath = value.get('cafilepath')
        certedhost = value.get('certedhost')
        if not isinstance(url, str) or not url.strip():
            raise ValueError('registrar source URL must be a non-empty string')
        if not isinstance(cafilepath, str) or not cafilepath.strip():
            raise ValueError('registrar source CA bundle must be a non-empty path')
        if certedhost is not None and (
                not isinstance(certedhost, str) or not certedhost.strip()):
            raise ValueError('registrar certificate hostname must be a non-empty string')

        url = url.strip()
        capath = Path(cafilepath).expanduser()
        certedhost = certedhost.strip() if certedhost is not None else None
        if not capath.is_absolute():
            raise ValueError('registrar source CA bundle path must be absolute')
        cafilepath = str(capath.resolve())
        if not Path(cafilepath).is_file():
            raise ValueError('registrar source CA bundle must be an existing file')
        try:
            target = urlsplit(url)
            target.port
        except ValueError as error:
            raise ValueError('registrar source URL is invalid') from error
        if (target.scheme != 'https' or not target.hostname
                or target.username is not None or target.password is not None
                or target.query or target.fragment):
            raise ValueError(
                'registrar source must be an HTTPS URL without credentials, query, or fragment')
        try:
            ipaddress.ip_address(target.hostname)
        except ValueError:
            if certedhost is not None:
                raise ValueError(
                    'registrar certificate hostname override requires an IP URL')
        else:
            if certedhost is None:
                raise ValueError(
                    'registrar IP URL requires an explicit certificate hostname')
        return cls(url=url, cafilepath=cafilepath, certedhost=certedhost)


def sourceTrusts(registrars, *, cafilepath=None, certedhosts=()):
    """Normalize CLI-style and per-source trust configuration.

    String registrars use the explicit shared ``cafilepath`` and require
    ``IP=hostname`` mappings for IP URLs.  Mapping registrars may supply those
    fields per source.  Every hostname mapping must name a configured IP source.
    """
    overrides = {}
    items = certedhosts.items() if isinstance(certedhosts, dict) else certedhosts
    for item in items:
        if isinstance(item, tuple) and len(item) == 2:
            address, hostname = item
        elif isinstance(item, str) and item.count('=') == 1:
            address, hostname = item.split('=', 1)
        else:
            raise ValueError('registrar certificate hostname must use IP=hostname')
        address, hostname = str(address).strip(), str(hostname).strip()
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError as error:
            raise ValueError('registrar certificate hostname key must be an IP address') from error
        if not hostname:
            raise ValueError('registrar certificate hostname must be non-empty')
        if address in overrides:
            raise ValueError(f'duplicate registrar certificate hostname for {address}')
        overrides[address] = hostname

    sources = []
    used = set()
    for registrar in registrars or ():
        if isinstance(registrar, str):
            target = urlsplit(registrar.strip())
            hostname = target.hostname
            try:
                address = str(ipaddress.ip_address(hostname)) if hostname else None
            except ValueError:
                address = None
            config = dict(url=registrar, cafilepath=cafilepath,
                          certedhost=overrides.get(address))
            if address in overrides:
                used.add(address)
        else:
            config = registrar
        sources.append(SourceTrust.fromConfig(config))
    unused = set(overrides) - used
    if unused:
        raise ValueError(
            f'registrar certificate hostname has no configured IP source: {sorted(unused)}')
    return tuple(sources)


logger = logging.getLogger(__name__)


class _RequestConfig:
    """Provide this service's mandatory KRAM configuration to the core owner."""
    def __init__(self, data):
        self.data = data

    def get(self):
        return self.data


def signedQuery(hab, route, attributes=None):
    """Sign one source query with the observer's real habitat keys."""
    serder = query(pre=hab.pre, route=route, query=attributes or {},
                   stamp=helping.nowIso8601(), version=Vrsn_2_0)
    return bytes(hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0))


class ObservedEvidence(doing.DoDoer):
    """Own native verification, source acquisition telemetry and public proofs."""
    def __init__(self, hby, *, baser=None, observations=None, sources=(), config=None):
        self.sources = tuple(SourceTrust.fromConfig(source) for source in sources)
        self.urls = frozenset(source.url for source in self.sources)
        self.hby = hby
        default = {"kram": {"enabled": True, "denials": [],
                   "caches": {"~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}
        self.cf = _RequestConfig(config if config is not None else default)
        policy = self.cf.get().get("kram", {})
        if policy.get("enabled") is not True or policy.get("denials"):
            raise ConfigurationError("service requests require enabled KRAM without denial exemptions")
        self.kvy = Kevery(db=hby.db, cf=self.cf, enableKram=True, lax=False, local=False)
        self.rgy = Regery(hby, baser=baser, name=hby.name, base=hby.base, temp=hby.temp)
        self.store = self.rgy.store
        self.pendingOpenings = Suber(db=self.rgy.baser, subkey="observer.pending-openings.")
        self.parser = Parser(kvy=self.kvy, rgy=self.rgy, local=False, version=Vrsn_2_0)
        self.pruner = Pruner(self.kvy.kramer, tock=1.0)
        self.observations = observations if observations is not None else ObservationBaser(
            name=hby.name, base=hby.base, temp=hby.temp)
        super().__init__(doers=[self.pruner, doing.doify(self.escrowDo)])

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Retry remote evidence using the scheduler's clock.

        Parameters:
            tymth: injected HIO clock; tock: cooperative retry interval.
            **kwa: unused scheduler metadata.
        Yields:
            float: delay before the next bounded escrow pass.
        """
        self.wind(tymth)
        yield tock
        while True:
            self.kvy.processEscrows()
            self.rgy.processEscrows()
            self._reconcileOpenings()
            yield tock


    def ingest(self, raw, *, publish=False):
        """Process public KEL/TEL evidence using the observer's concrete owners.

        Only an authorized publisher opts into retaining disclosed openings.
        Acceptance and dependency persistence belong to Kevery and Regery;
        this method reports their final outcomes without another pending queue.
        """
        ims = bytearray(raw)
        summary = dict(accepted={}, pending={}, rejected={}, heads={})
        events, dependencies, disclosures = [], [], []
        while ims:
            serder = None
            try:
                before = len(ims)
                dom = self.parser.parseOneBare(ims=ims, processive=False, local=False)
                if dom is None or dom.serder is None or len(ims) >= before:
                    raise ValidationError("invalid or incomplete evidence frame")
                serder = dom.serder
                if isinstance(serder, SerderACDC):
                    opening = self._disclosedOpening(serder, dom)
                    self.rgy.processEvent(serder, sscs=dom.sscs, ssts=dom.ssts)
                    events.append(serder)
                    if publish and opening is not None:
                        disclosures.append((serder, opening))
                else:
                    if serder.ilk not in ("icp", "dip", "rot", "drt", "ixn", "rct"):
                        raise ValidationError("observer intake accepts only public KEL and native TEL")
                    self.parser.msgProcess(asdict(dom), kvy=self.kvy, tvy=None,
                                           exc=None, rvy=None, vry=None)
            except (MissingSignatureError, MissingWitnessSignatureError,
                    MissingDelegationError, OutOfOrderError,
                    MissingDelegableApprovalError, UnverifiedReceiptError,
                    UnverifiedWitnessReceiptError,
                    UnverifiedTransferableReceiptError) as ex:
                if serder is not None and not isinstance(serder, SerderACDC) and self._kelPending(serder):
                    dependencies.append(serder)
                    continue
                summary["rejected"]["stream"] = str(ex) or type(ex).__name__
                break
            except Exception as ex:
                summary["rejected"]["stream"] = str(ex) or type(ex).__name__
                break
        self.kvy.processEscrows()
        self.rgy.processEscrows()
        for event in dependencies:
            if self._kelPending(event):
                key = f"kel:{event.pre}"
                summary["pending"][key] = summary["pending"].get(key, 0) + 1
            elif self.hby.db.kels.getLast(keys=event.pre, on=event.sn) != event.said:
                summary["rejected"][f"kel:{event.pre}:{event.snh}"] = "dependency was not accepted or retained"
        for event in events:
            regk = event.said if event.ilk == "rip" else event.sad["rd"]
            sn = Number(numh=event.sad["n"]).num
            accepted = self.store.seqSaider(regk, sn)
            if accepted is not None and accepted.qb64 == event.said:
                bucket = "accepted"
                previous = summary["heads"].get(regk)
                if previous is None or Number(numh=self.store.event(previous).sad["n"]).num < sn:
                    summary["heads"][regk] = event.said
            else:
                pending = self._telPending(event)
                bucket = "pending" if pending else "rejected"
            summary[bucket][regk] = summary[bucket].get(regk, 0) + 1
        for event, opening in disclosures:
            accepted = self.store.seqSaider(event.sad["rd"], Number(numh=event.sad["n"]).num)
            if accepted is not None and accepted.qb64 == event.said:
                self.store.putOpening(event.said, opening)
            elif self._telPending(event):
                existing = self.pendingOpenings.get(event.said)
                if existing is not None and existing != opening.qb64:
                    raise ValidationError("pending public opening is immutable")
                self.pendingOpenings.put(event.said, opening.qb64)
        self._reconcileOpenings()
        return summary


    def _disclosedOpening(self, event, dom):
        """Validate an explicitly supplied opening before native TEL processing."""
        from keri.acdc.regeventing import vetBlind
        supplied = [(BlindState, values) for values in dom.bsqs]
        supplied.extend((BoundState, values) for values in dom.bsss)
        if not supplied:
            return None
        if event.ilk != "bup" or len(supplied) != 1:
            raise ValidationError("only a BUP may carry one disclosed opening")
        clan, values = supplied[0]
        opening = Blinder(data=clan(*values))
        vetBlind(opening, blid=event.sad["b"])
        return opening


    def _telPending(self, event):
        """Match the exact BUP/RIP in the core's ordinary dependency escrow."""
        regk = event.said if event.ilk == "rip" else event.sad["rd"]
        sn = Number(numh=event.sad["n"]).num
        return any((event.said,) in escrow.get(keys=regk, on=sn)
                   for escrow in (self.rgy.baser.maes, self.rgy.baser.ooes))


    def _reconcileOpenings(self):
        """Promote authorized disclosures only after accepted TEL membership.

        Keep exact core dependencies across restart, without a second body
        queue or retry service. Removed/rejected dependencies lose their proof.
        """
        from keri.acdc.regeventing import vetBlind
        for (said,), raw in list(self.pendingOpenings.getTopItemIter()):
            event = self.store.event(said)
            try:
                if event is None or event.ilk != "bup":
                    raise ValidationError("pending public opening has no BUP")
                vetBlind(raw, blid=event.sad["b"])
                accepted = self.store.seqSaider(event.sad["rd"], Number(numh=event.sad["n"]).num)
                if accepted is not None and accepted.qb64 == said:
                    for clan in (BlindState, BoundState):
                        try:
                            opening = Blinder(clan=clan, qb64=raw)
                        except (KeriError, ValueError, TypeError):
                            continue
                        if opening.qb64 == raw:
                            self.store.putOpening(said, opening)
                            break
                    else:
                        raise ValidationError("invalid pending public opening")
                elif self._telPending(event):
                    continue
            except (KeriError, ValueError, TypeError):
                logger.warning("Discarding invalid pending public opening %s", said)
            self.pendingOpenings.rem(said)


    def _kelPending(self, event):
        """Report only exact dependencies retained by the ordinary KEL escrows."""
        db = self.hby.db
        if event.ilk != "rct":
            if any(event.said in escrow.get(keys=event.pre, on=event.sn)
                   for escrow in (db.pses, db.pwes, db.pdes, db.ooes)):
                return True
            return event.said in db.delegables.get(keys=snKey(event.pre, event.sn))
        if any(said == event.said for said, _ in db.uwes.get(keys=event.pre, on=event.sn)):
            return True
        receipts = db.ures.get(keys=(event.pre, Number(num=event.sn, code=NumDex.Huge).qb64))
        receipts += db.vres.get(keys=snKey(event.pre, event.sn))
        return any(receipt[0].qb64 == event.said for receipt in receipts)


    def clone(self, regks=None, sn=0):
        """Export accepted KEL/TEL and openings explicitly disclosed here.

        Core TEL cloning remains body-only. This service attaches held material
        from explicit configured-source acquisition only.
        """
        kel, tel, issuers = bytearray(), bytearray(), set()
        for regk in self.registries() if regks is None else regks:
            rip = self.store.seqEvent(regk, 0)
            if rip is None:
                raise KeyError(regk)
            issuer = rip.sad["i"]
            if issuer not in issuers:
                kel.extend(b"".join(self.hby.db.cloneDelegation(self.hby.kevers[issuer], gvrsn=Vrsn_2_0)))
                kel.extend(b"".join(self.hby.db.clonePreIter(pre=issuer, gvrsn=Vrsn_2_0)))
                issuers.add(issuer)
            for raw in self.store.cloneTelIter(regk, sn=sn):
                event = SerderACDC(raw=raw)
                opening = self.store.opening(event.said) if event.ilk == "bup" else None
                attachments = Blinder.enclose([opening]) if opening is not None else b""
                tel.extend(event.raw)
                tel.extend(Counter.enclose(qb64=attachments, code=Codens.AttachmentGroup,
                                          version=Vrsn_2_0))
        return bytes(kel + tel)


    def registries(self):
        """Enumerate accepted registry heads, excluding staged bodies."""
        return sorted(keys[0] for keys, _ in self.rgy.baser.heads.getTopItemIter())

    def pendingInScope(self, regks):
        """Find unresolved ordinals in this scope, ignoring already accepted slots."""
        scope = set(regks)
        return any(keys[0] in scope and self.store.seqSaider(keys[0], sn) is None
                   for escrow in (self.rgy.baser.maes, self.rgy.baser.ooes)
                   for keys, sn, _ in escrow.getTopItemIter())

    def observe(self, url, raw):
        """Retain disclosed public proof only for configured-source acquisition.

        Completion records describe the source pull, never credential authority
        or a freshness prerequisite for serving independently accepted history.
        """
        result = self.ingest(raw, publish=url in self.urls)
        previous = self.observations.observations.get((url,))
        heads = result['heads']
        scope = set(heads) | (set(previous.heads) if previous else set())
        pending = self.pendingInScope(scope)
        complete = not previous or set(previous.heads).issubset(heads)
        complete = complete and all(self.store.head(regk).qb64 == said
                                    for regk, said in heads.items())
        if (url in self.urls and not result['rejected'] and not result['pending']
                and not pending and complete):
            self.observations.observations.pin(
                keys=(url,), val=Observation(helping.nowIso8601(), heads))
        return result

    def close(self):
        """Release owned source and registry stores after worker cancellation."""
        if self.observations.opened:
            self.observations.close()
        if self.store.opened:
            self.rgy.close()


class SourceClientDoer(http.clienting.ClientDoer):
    """Contain socket and TLS failures for one source acquisition."""
    def __init__(self, client, **kwa):
        """Wrap client with ordinary HIO options kwa and start without a captured error."""
        super().__init__(client, **kwa)
        self.error = None

    def recur(self, tyme):
        """Service the client at scheduler time tyme; return True on expected failure.

        Retain socket/TLS or decoder errors for the pull owner to inspect rather than
        raising them through the sibling service scheduler.
        """
        try:
            return super().recur(tyme)
        except (OSError, ValueError) as error:
            self.error = error
            return True


class RegistrarPuller(doing.DoDoer):
    """Poll authenticated configured sources sequentially on a fixed cadence."""
    def __init__(self, hab, observer, sources, *, interval=5.0,
                 timeout=5.0, tock=0.03125):
        """Configure signed source acquisition for hab and observer's evidence cache.

        sources selects explicit trusted endpoints; interval controls polling, timeout
        bounds each request and tock controls HIO scheduling. Invalid timing raises
        ValueError. This owner schedules acquisition, not a new evidence acceptor.
        """
        if not isfinite(interval) or not isfinite(timeout) or interval <= 0 or timeout <= 0:
            raise ValueError('poll interval and timeout must be finite and positive')
        self.hab, self.observer = hab, observer
        self.sources = tuple(SourceTrust.fromConfig(source) for source in sources)
        self.urls = tuple(source.url for source in self.sources)
        self.interval, self.timeout = interval, timeout
        self.results = deque(maxlen=32)
        self.status = {}
        self.client = None
        super().__init__(doers=[doing.doify(self.pollDo)], tock=tock)

    def record(self, url, result):
        """Retain, log and expose the latest outcome of one source pull.

        Evidence results become valid, pending, revoked (a held opening of an
        accepted head states revocation) or refused with the first rejection
        reason; transport and HTTP failures keep their own labels. Only the last
        outcome per source is kept, so no new store or history is introduced.
        """
        self.results.append((url, result))
        if isinstance(result, dict) and 'transport_error' in result:
            outcome, reason = 'transport_error', result['transport_error']
        elif isinstance(result, dict):
            outcome, reason = 'valid', None
            if result['rejected']:
                outcome, reason = 'refused', next(iter(result['rejected'].values()))
            elif result['pending']:
                outcome = 'pending'
            else:
                for said in result['heads'].values():
                    opening = self.observer.store.opening(said)
                    if opening is not None and opening.state == 'revoked':
                        outcome = 'revoked'
        else:
            outcome, reason = result, None
        entry = dict(outcome=outcome, reason=reason, lastPull=helping.nowIso8601())
        self.status[url] = entry
        if outcome in ('valid', 'pending', 'revoked'):
            logger.info("Source %s pull outcome=%s", url, outcome)
        else:
            logger.warning("Source %s pull outcome=%s reason=%s", url, outcome, reason)

    def pollDo(self, tymth=None, tock=0.03125, **kwa):
        """Acquire one bounded response without letting TLS failure stop peers."""
        self.wind(tymth)
        yield tock
        while True:
            started = self.tyme
            for source in self.sources:
                url = source.url
                target = urlsplit(url)
                client = None
                doer = None
                try:
                    # HIO also needs cafilepath to avoid reloading system roots.
                    client = http.clienting.Client(
                        scheme='https', hostname=target.hostname, port=target.port or 443,
                        context=ssl.create_default_context(cafile=source.cafilepath),
                        cafilepath=source.cafilepath, certedhost=source.certedhost,
                        redirectable=False)
                    doer = SourceClientDoer(client=client)
                    self.extend([doer])
                    self.client = client
                    client.request(method='POST', path=target.path or '/',
                        headers={'Content-Type': CESR_CONTENT_TYPE},
                        body=signedQuery(self.hab, 'tels/bulk'))
                    deadline = self.tyme + self.timeout
                    while (not client.responses and doer.error is None
                           and self.tyme < deadline):
                        yield tock
                    if doer.error is not None:
                        self.record(url, {'transport_error': str(doer.error)})
                    elif not client.responses:
                        self.record(url, 'timeout')
                    else:
                        response = client.responses.popleft()
                        if response['status'] != 200:
                            self.record(url, 'http_error')
                        elif (response.get('headers', {}).get('content-type', '').split(';')[0]
                              != CESR_CONTENT_TYPE):
                            self.record(url, 'invalid_content_type')
                        else:
                            result = self.observer.observe(url, response['body'])
                            self.record(url, result)
                except OSError as error:
                    self.record(url, {'transport_error': str(error)})
                finally:
                    if doer is not None and doer in self.doers:
                        self.remove([doer])
                    if client is not None:
                        client.close()
                    self.client = None
            while self.tyme < started + self.interval:
                yield tock
