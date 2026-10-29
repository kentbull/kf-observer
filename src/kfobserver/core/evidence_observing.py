"""Full-evidence observation persistence and authenticated source polling.

This application owns configured-source acquisition.  KERIpy still
owns the shared evidence processors and durable registry stores.
"""
from collections import deque
from dataclasses import dataclass, field
import ipaddress
from math import isfinite
from pathlib import Path
from urllib.parse import urlsplit

from hio.base import doing
from hio.core import http
from keri.app.evidencing import EvidenceContext, signedQuery
from keri.app.httping import CESR_CONTENT_TYPE
from keri.db import dbing, koming
from keri.help import helping



@dataclass
class Observation:
    """Durable completed-pull time and exact accepted heads for one source URL."""
    completed: str = ''
    heads: dict = field(default_factory=dict)


class ObservationBaser(dbing.LMDBer):
    """Caller-owned LMDB persistence for completed source observations."""
    TailDirPath = 'keri/observer'
    AltTailDirPath = '.keri/observer'

    def reopen(self, **kwa):
        """Open the existing ``observations.`` URL-keyed records unchanged."""
        super().reopen(**kwa)
        self.observations = koming.Komer(
            db=self, subkey='observations.', klas=Observation)
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


class ObservedEvidence(EvidenceContext):
    """Own service stores and share KERIpy verification for source observations.

    Registry and observation stores supplied to this application context transfer
    lifecycle ownership to it; the supplied Habery remains caller-owned.
    """
    def __init__(self, hby, *, observations=None,
                 sources=(), **kwa):
        """Borrow hby and configure source identities with an owned observation store.

        observations supplies the store to close with this context, or None opens one.
        sources supplies explicit trust configuration; kwa configures shared evidence
        processors. Construction does not fetch remote evidence.
        """
        super().__init__(hby, **kwa)
        self.sources = tuple(SourceTrust.fromConfig(source) for source in sources)
        self.urls = frozenset(source.url for source in self.sources)
        self.observations = observations if observations is not None else ObservationBaser(
            name=hby.name, base=hby.base, temp=hby.temp)

    def pendingInScope(self, regks):
        """Find unresolved TEL ordinals in this scope, ignoring accepted slots."""
        scope = set(regks)
        return any(keys[0] in scope and self.store.seqSaider(keys[0], sn) is None
                   for escrow in (self.reger.maes, self.reger.ooes)
                   for keys, sn, _ in escrow.getTopItemIter())

    def observe(self, url, raw):
        """Record a complete pull over returned and prior successful URL membership."""
        result = self.ingest(raw)
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
        """Release service stores after cancellation, leaving Habery open."""
        self.observations.close()
        self.reger.close()


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
        self.client = None
        super().__init__(doers=[doing.doify(self.pollDo)], tock=tock)

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
                    client = http.clienting.Client(
                        scheme='https', hostname=target.hostname, port=target.port or 443,
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
                        self.results.append((url, {'transport_error': str(doer.error)}))
                    elif not client.responses:
                        self.results.append((url, 'timeout'))
                    else:
                        response = client.responses.popleft()
                        if response['status'] != 200:
                            self.results.append((url, 'http_error'))
                        elif (response.get('headers', {}).get('content-type', '').split(';')[0]
                              != CESR_CONTENT_TYPE):
                            self.results.append((url, 'invalid_content_type'))
                        else:
                            result = self.observer.observe(url, response['body'])
                            self.results.append((url, result))
                except OSError as error:
                    self.results.append((url, {'transport_error': str(error)}))
                finally:
                    if doer is not None and doer in self.doers:
                        self.remove([doer])
                    if client is not None:
                        client.close()
                    self.client = None
            while self.tyme < started + self.interval:
                yield tock
