"""Full-evidence observer profile over the shared, qualified native core.

This package owns service configuration, role policy and process lifecycle.
KERIpy owns evidence verification, cooperative acquisition and exact-head source
observations. The original bare-TEL adapter remains separately selectable.
"""
from pathlib import Path

import falcon
from hio.core import http
from keri.app.evidence_httping import HealthEnd
from keri.app.evidence_observing import ObservedEvidence, RegistrarPuller
from keri.app.evidence_querying import QueryEnd
from keri.app.indirecting import createHttpServer
from keri.db.basing import BaserDoer
from keri.kering import ConfigurationError


class Context(ObservedEvidence):
    """Compose this fork's authorized cache API over shared observation state."""

    def __init__(self, hby, *, readers=(), **kwa):
        """Attach reader policy and routes without scheduling acquisition.

        Parameters:
            hby: caller-owned habitat environment.
            readers: AIDs explicitly authorized for native cache queries.
            **kwa: shared stores, source URLs, freshness age and KRAM settings.
        """
        super().__init__(hby, **kwa)
        self.readers = set(readers)
        self.app = falcon.App()
        self.app.add_route("/", QueryEnd(self))
        self.app.add_route("/health", HealthEnd())


def setup(hby, *, alias="observer", host="127.0.0.1", port=6633,
          registrars=(), readers=(), kel=(), maximumAge=15.0, interval=5.0,
          timeout=5.0, keypath=None, certpath=None, cafilepath=None):
    """Construct the external observer runtime and verify bootstrap before bind.

    Parameters:
        hby: caller-owned Habery; alias: local query-signing habitat name.
        host, port: listener address; registrars: independent full-proof sources.
        readers: authorized cache requester AIDs; kel: signed bootstrap paths.
        maximumAge: positive finite source-observation age in seconds.
        interval, timeout: cooperative polling cadence and per-source deadline.
        keypath, certpath, cafilepath: optional HTTP TLS configuration paths.
    Returns:
        tuple: context and doers. Cancel workers before closing the context.
    Raises:
        ConfigurationError: no source/readers or incomplete bootstrap.
        ValueError: invalid freshness/poll timing policy.

    A presentation query never starts or accelerates a registrar pull. Witness
    receipts and delegation evidence arrive in the full source stream and are
    checked by the ordinary KEL processor before registry acceptance.
    """
    if not registrars or not readers:
        raise ConfigurationError("full-evidence observer requires registrars and readers")
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=True)
    ctx = Context(hby, readers=readers, urls=registrars, maximumAge=maximumAge)
    server = None
    try:
        for path in kel:
            result = ctx.ingest(Path(path).read_bytes())
            if result["rejected"] or result["pending"]:
                raise ConfigurationError("observer bootstrap evidence is incomplete or invalid")
        poller = RegistrarPuller(hab, ctx, registrars, interval=interval, timeout=timeout)
        server = createHttpServer(host=host, port=port, app=ctx.app,
            keypath=keypath, certpath=certpath, cafilepath=cafilepath)
        return ctx, [BaserDoer(baser=ctx.reger), BaserDoer(baser=ctx.observations),
                     ctx, http.ServerDoer(server=server), poller]
    except BaseException:
        if server is not None:
            server.close()
        ctx.close()
        raise
