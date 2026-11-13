"""Full-evidence observer profile over ordinary KERIpy processors.

This package owns service configuration, role policy and process lifecycle.
KERIpy owns evidence verification and stores.  This application owns source
acquisition, observations, query policy, and process lifecycle.
"""
from pathlib import Path

import falcon
from hio.core import http
from keri.app.indirecting import createHttpServer
from keri.app.tocking import TOCKS, Tock, resolveTocks
from keri.db.basing import BaserDoer
from keri.core import Prefixer
from keri.kering import ConfigurationError, KeriError

from kfobserver.core.evidence_observing import (
    ObservedEvidence, ReaderAccount, RegistrarPuller, sourceTrusts)
from kfobserver.app.httping import preflightEnrollmentKel
from kfobserver.core.evidence_querying import QueryEnd

# 1.25 ms rather than KERIpy's 10 ms default: the observer answers reader queries
# and drives registrar pulls on their latency path, so its tick was set for response
# time over idle CPU. KERI_DOIST_TOCK or a tocks.doist config value still overrides it.
OBSERVER_DOIST_TOCK = 0.00125
OBSERVER_TOCKS = TOCKS | {"doist": Tock(env=TOCKS["doist"].env, default=OBSERVER_DOIST_TOCK)}


def doistTock(cfTocks=None):
    """Return the observer Doist tick from KERIpy's tock precedence.

    KERI_DOIST_TOCK wins, then cfTocks["doist"] (a config file's tocks object),
    then OBSERVER_DOIST_TOCK. Invalid values raise ConfigurationError.
    """
    return resolveTocks(cfTocks, tocks=OBSERVER_TOCKS)["doist"]


class HealthEnd:
    """Report listener availability without making an evidence claim."""
    def __init__(self, sources=None):
        """Bind an optional zero-argument callable returning per-source pull outcomes."""
        self.sources = sources

    def on_get(self, req, rep):
        """Set the Falcon response media to local listener health; req is unused.

        The private listener adds the last pull outcome per configured source
        (outcome, reason, lastPull); the public listener reports status only.
        """
        rep.media = {'status': 'ok'}
        if self.sources is not None:
            rep.media['sources'] = self.sources()


def _validAccountAid(aid):
    """Accept exactly one complete prefix using the core's ordinary AID codec."""
    try:
        return Prefixer(qb64=aid).qb64 == aid
    except (KeriError, ValueError, TypeError):
        return False


class AccountEnd:
    """Private loopback enrollment over ordinary accepted public KEL evidence."""
    def __init__(self, ctx):
        self.ctx = ctx

    def validate(self, aid):
        """Validate the full account prefix and explicit borrowed service habitat."""
        if not _validAccountAid(aid):
            raise falcon.HTTPBadRequest(description="account must be one complete AID")
        if self.ctx.hab is None:
            raise falcon.HTTPServiceUnavailable(description="service habitat is unavailable")

    def record(self, aid):
        """Report a durable dynamic account using the actual service identity."""
        account = self.ctx.observations.accounts.get((aid,))
        if account is None:
            raise falcon.HTTPNotFound(description="account is not enrolled")
        return dict(aid=aid, roles=account.roles, service=self.ctx.hab.pre)

    def on_put(self, req, rep, aid):
        """Persist authorization before publishing it to the live query policy."""
        self.validate(aid)
        payload = req.media
        if (not isinstance(payload, dict) or set(payload) != {'roles', 'kel'}
                or payload['roles'] != ['reader'] or not isinstance(payload['kel'], str)):
            raise falcon.HTTPBadRequest(description="expected roles ['reader'] and public KEL string")
        raw = payload['kel'].encode('utf-8')
        preflightEnrollmentKel(raw)
        result = self.ctx.ingest(raw)
        if result['rejected'] or result['pending']:
            raise falcon.HTTPConflict(description="enrollment KEL is refused or incomplete")
        if aid not in self.ctx.hby.kevers:
            raise falcon.HTTPConflict(description="account AID is not accepted")
        self.ctx.observations.accounts.pin((aid,), ReaderAccount(roles=['reader']))
        self.ctx.readers.add(aid)
        rep.media = self.record(aid)

    def on_get(self, req, rep, aid):
        self.validate(aid)
        rep.media = self.record(aid)

    def on_delete(self, req, rep, aid):
        """Revoke only dynamic authorization; fixed operator readers remain active."""
        self.validate(aid)
        self.ctx.observations.accounts.rem((aid,))
        if aid not in self.ctx.staticReaders:
            self.ctx.readers.discard(aid)
        rep.status = falcon.HTTP_204


class Context(ObservedEvidence):
    """Compose this fork's authorized cache API over shared observation state."""

    def __init__(self, hby, *, readers=(), hab=None, **kwa):
        """Attach reader policy and routes without scheduling acquisition.

        Parameters:
            hby: caller-owned habitat environment.
            hab: explicit borrowed service identity for private enrollment.
            readers: AIDs explicitly authorized for ACDC v2 registry cache queries.
            **kwa: shared stores, source trust and KRAM settings.
        """
        super().__init__(hby, **kwa)
        self.hab = hab
        self.staticReaders = set(readers)
        self.readers = self.staticReaders.copy()
        try:
            for keys, account in self.observations.accounts.getTopItemIter():
                aid = keys[0]
                if (len(keys) != 1 or not _validAccountAid(aid)
                        or account.roles != ['reader'] or aid not in hby.kevers):
                    raise ConfigurationError("invalid or unaccepted enrolled observer account")
                self.readers.add(aid)
        except BaseException:
            self.close()
            raise
        self.internalApp = falcon.App()
        self.sourceStatus = {}
        self.internalApp.add_route("/health", HealthEnd(lambda: dict(self.sourceStatus)))
        self.internalApp.add_route("/accounts/{aid}", AccountEnd(self))
        self.app = falcon.App()
        self.app.add_route("/", QueryEnd(self))
        self.app.add_route("/health", HealthEnd())


def setup(hby, *, alias="observer", host="127.0.0.1", port=6633, bootport=6634,
          registrars=(), readers=(), kel=(), interval=5.0,
          timeout=5.0, registrarCafilepath=None, registrarCertedhosts=(),
          keypath=None, certpath=None, cafilepath=None):
    """Construct the external observer runtime and verify bootstrap before bind.

    Parameters:
        hby: caller-owned Habery; alias: local query-signing habitat name.
        bootport: private loopback-only enrollment listener.
        host, port: public listener address; registrars: independent full-proof sources.
        registrarCafilepath: explicit outbound source CA bundle for URL entries.
        registrarCertedhosts: required IP=certificate-hostname mappings for IP URLs.
        readers: authorized cache requester AIDs; kel: signed bootstrap paths.
        interval, timeout: cooperative polling cadence and per-source deadline.
        keypath, certpath, cafilepath: optional HTTP TLS configuration paths.
    Returns:
        tuple: context and doers. Cancel workers before closing the context.
    Raises:
        ConfigurationError: no sources, conflicting listeners or incomplete bootstrap.
        ValueError: invalid poll timing policy.

    A presentation query never starts or accelerates a registrar pull. Witness
    receipts and delegation evidence arrive in the full source stream and are
    checked by the ordinary KEL processor before registry acceptance.
    """
    if not registrars:
        raise ConfigurationError("full-evidence observer requires authenticated registrars")
    if port == bootport:
        raise ConfigurationError("observer public and private boot ports must differ")
    sources = sourceTrusts(registrars, cafilepath=registrarCafilepath,
                           certedhosts=registrarCertedhosts)
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=True)
    ctx = Context(hby, readers=readers, hab=hab, sources=sources)
    server = bootServer = None
    try:
        for path in kel:
            result = ctx.ingest(Path(path).read_bytes())
            if result["rejected"] or result["pending"]:
                raise ConfigurationError("observer bootstrap evidence is incomplete or invalid")
        poller = RegistrarPuller(hab, ctx, sources, interval=interval, timeout=timeout)
        ctx.sourceStatus = poller.status
        server = createHttpServer(host=host, port=port, app=ctx.app,
            keypath=keypath, certpath=certpath, cafilepath=cafilepath)
        bootServer = createHttpServer(host="127.0.0.1", port=bootport, app=ctx.internalApp)
        return ctx, [BaserDoer(baser=ctx.rgy.baser), BaserDoer(baser=ctx.observations),
                     ctx, http.ServerDoer(server=server), http.ServerDoer(server=bootServer), poller]
    except BaseException:
        if bootServer is not None:
            bootServer.close()
        if server is not None:
            server.close()
        ctx.close()
        raise
