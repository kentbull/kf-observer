"""Full-evidence observer profile over the shared KERIpy evidence core.

This package owns service configuration, role policy and process lifecycle.
KERIpy owns evidence verification and stores.  This application owns source
acquisition, observations, query policy, and process lifecycle.  The original
bare-TEL adapter remains separately selectable.
"""
from pathlib import Path

import falcon
from hio.core import http
from keri.app.indirecting import createHttpServer
from keri.db.basing import BaserDoer
from keri.kering import ConfigurationError

from kfobserver.core.evidence_observing import (
    ObservedEvidence, RegistrarPuller, sourceTrusts)
from kfobserver.core.evidence_querying import QueryEnd


class HealthEnd:
    """Report listener availability without making an evidence claim."""
    def on_get(self, req, rep):
        rep.media = {'status': 'ok'}


class Context(ObservedEvidence):
    """Compose this fork's authorized cache API over shared observation state."""

    def __init__(self, hby, *, readers=(), **kwa):
        """Attach reader policy and routes without scheduling acquisition.

        Parameters:
            hby: caller-owned habitat environment.
            readers: AIDs explicitly authorized for ACDC v2 registry cache queries.
            **kwa: shared stores, source trust and KRAM settings.
        """
        super().__init__(hby, **kwa)
        self.readers = set(readers)
        self.app = falcon.App()
        self.app.add_route("/", QueryEnd(self))
        self.app.add_route("/health", HealthEnd())


def setup(hby, *, alias="observer", host="127.0.0.1", port=6633,
          registrars=(), readers=(), kel=(), interval=5.0,
          timeout=5.0, registrarCafilepath=None, registrarCertedhosts=(),
          keypath=None, certpath=None, cafilepath=None):
    """Construct the external observer runtime and verify bootstrap before bind.

    Parameters:
        hby: caller-owned Habery; alias: local query-signing habitat name.
        host, port: listener address; registrars: independent full-proof sources.
        registrarCafilepath: explicit outbound source CA bundle for URL entries.
        registrarCertedhosts: required IP=certificate-hostname mappings for IP URLs.
        readers: authorized cache requester AIDs; kel: signed bootstrap paths.
        interval, timeout: cooperative polling cadence and per-source deadline.
        keypath, certpath, cafilepath: optional HTTP TLS configuration paths.
    Returns:
        tuple: context and doers. Cancel workers before closing the context.
    Raises:
        ConfigurationError: no source/readers or incomplete bootstrap.
        ValueError: invalid poll timing policy.

    A presentation query never starts or accelerates a registrar pull. Witness
    receipts and delegation evidence arrive in the full source stream and are
    checked by the ordinary KEL processor before registry acceptance.
    """
    if not registrars or not readers:
        raise ConfigurationError("full-evidence observer requires registrars and readers")
    sources = sourceTrusts(registrars, cafilepath=registrarCafilepath,
                           certedhosts=registrarCertedhosts)
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=True)
    ctx = Context(hby, readers=readers, sources=sources)
    server = None
    try:
        for path in kel:
            result = ctx.ingest(Path(path).read_bytes())
            if result["rejected"] or result["pending"]:
                raise ConfigurationError("observer bootstrap evidence is incomplete or invalid")
        poller = RegistrarPuller(hab, ctx, sources, interval=interval, timeout=timeout)
        server = createHttpServer(host=host, port=port, app=ctx.app,
            keypath=keypath, certpath=certpath, cafilepath=cafilepath)
        return ctx, [BaserDoer(baser=ctx.reger), BaserDoer(baser=ctx.observations),
                     ctx, http.ServerDoer(server=server), poller]
    except BaseException:
        if server is not None:
            server.close()
        ctx.close()
        raise
