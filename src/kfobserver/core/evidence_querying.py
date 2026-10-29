"""Authenticated cache-only query policy for the full-evidence profile."""
import falcon
from keri import Vrsn_2_0
from keri.core import Parser

from keri.app.httping import CESR_CONTENT_TYPE
from keri.kering import ValidationError


# Service HTTP policy moved from KERIpy aea8fbc6 evidence_httping.py.
# KRAM remains the protocol authority; no cross-service adapter package is needed.
def authenticate(req, ctx, allowed, routes):
    """Authenticate one complete KERI v2 signed query and enforce the service allowlist.

        Args:
            req: Falcon request carrying one signed CESR query in its bounded body.
            ctx (Context): Service holding enabled KRAM and authenticated KEL evidence.
            allowed (Collection[str]): Explicit requester AIDs permitted for this route.
            routes (Collection[str]): Query routes this endpoint accepts.

        Returns:
            tuple: Authenticated query Serder and its query-attribute map.

        Raises:
            falcon.HTTPError: Unsupported media, malformed/multiple messages, forbidden
                AID/route, unavailable authentication, or invalid/replayed evidence.

        Authorization alone cannot authenticate input. KRAM verifies the exact request
        and updates replay/liveness state before endpoint code consumes its payload."""
    if (req.content_type or '').split(';')[0].lower() != CESR_CONTENT_TYPE:
        raise falcon.HTTPUnsupportedMediaType()
    ims = bytearray(req.bounded_stream.read())
    if not ims:
        raise falcon.HTTPBadRequest(description='empty query')
    try:
        dom = Parser(version=Vrsn_2_0).parseOne(ims=ims, processive=False, local=False)
        if dom is None or dom.serder is None or ims:
            raise ValueError('expected exactly one complete signed query')
        serder = dom.serder
        if serder.ilk != 'qry' or serder.pvrsn != Vrsn_2_0:
            raise ValueError('expected a KERI v2 signed query')
    except Exception as ex:
        raise falcon.HTTPBadRequest(description=str(ex)) from ex
    if serder.route not in routes or serder.pre not in allowed:
        raise falcon.HTTPForbidden(description='requester or route is not authorized')
    if not ctx.kvy.kramer or not ctx.kvy.kramer.enabled:
        raise falcon.HTTPServiceUnavailable(description='request authentication unavailable')
    try:
        kwa = {key: getattr(dom, key) for key in ('sigers', 'cigars', 'lsgs', 'tsgs', 'sscs', 'ssts')}
        if ctx.kvy.kramer.intake(serder, kwa) is None:
            raise ValueError('KRAM rejected request')
    except Exception as ex:
        raise falcon.HTTPUnauthorized(description=str(ex)) from ex
    qry = serder.sad.get('q')
    if not isinstance(qry, dict):
        raise falcon.HTTPBadRequest(description='query must be an object')
    return serder, qry



class QueryEnd:
    """Serve accepted local registry history after ordinary query authentication."""
    def __init__(self, ctx):
        self.ctx = ctx

    def on_post(self, req, rep):
        _, qry = authenticate(req, self.ctx, self.ctx.readers,
                              ('tels', 'tels/head'))
        regk = qry.get('i')
        if not isinstance(regk, str) or not regk or 'vcid' in qry:
            raise falcon.HTTPBadRequest(description='q.i must identify one registry')
        if self.ctx.pendingInScope((regk,)):
            raise falcon.HTTPServiceUnavailable(
                description='registry dependencies are pending')
        if self.ctx.store.head(regk) is None:
            raise falcon.HTTPNotFound(
                description='unknown registry in local observer cache')
        sn = qry.get('sn', 0)
        if not isinstance(sn, int) or sn < 0:
            raise falcon.HTTPBadRequest(
                description='sn must be a nonnegative integer')
        try:
            rep.data = self.ctx.clone([regk], sn=sn)
        except ValidationError as ex:
            raise falcon.HTTPServiceUnavailable(
                description='registry history is outside the supported evidence profile') from ex
        rep.content_type = CESR_CONTENT_TYPE
