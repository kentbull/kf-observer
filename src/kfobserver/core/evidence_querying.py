"""Authenticated cache-only query policy for the full-evidence profile."""
import falcon
from keri.core import Number

from keri.app.httping import CESR_CONTENT_TYPE
from keri.kering import ValidationError
from kfobserver.app.httping import _parseQuery, _authenticateQuery, introduceKel


class QueryEnd:
    """Serve accepted local registry history after ordinary query authentication."""
    def __init__(self, ctx):
        """Borrow ctx for reader policy and its already verified local registry cache."""
        self.ctx = ctx

    def on_post(self, req, rep):
        """Authenticate Falcon req and write cached, accepted evidence to rep.

        Only configured readers may query tels/tels/head. Invalid scope is rejected;
        missing history or pending dependencies yield HTTP errors. A read never pulls
        from an upstream source or claims new observation freshness.
        """
        serder, qry = _authenticateQuery(_parseQuery(req), self.ctx, self.ctx.readers,
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
        if serder.route == "tels/head":
            sn = Number(numh=self.ctx.store.headEvent(regk).sad["n"]).num
        try:
            rep.data = self.ctx.clone([regk], sn=sn)
        except ValidationError as ex:
            raise falcon.HTTPServiceUnavailable(
                description='registry history is outside the supported evidence profile') from ex
        rep.content_type = CESR_CONTENT_TYPE

    def on_get(self, req, rep):
        raise falcon.HTTPMethodNotAllowed(["POST", "PUT"])

    def on_put(self, req, rep):
        """Introduce authenticated public KEL without initiating source polling."""
        introduceKel(req, rep, self.ctx)
