"""Authenticated cache-only query policy for the full-evidence profile."""
import falcon

from keri.app.evidence_httping import authenticate
from keri.app.httping import CESR_CONTENT_TYPE
from keri.kering import ValidationError



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
