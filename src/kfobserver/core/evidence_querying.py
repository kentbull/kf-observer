"""Authenticated cache-only query policy for the full-evidence profile."""
import falcon

from keri.app.evidence_httping import authenticate
from keri.app.httping import CESR_CONTENT_TYPE
from keri.help import helping
from keri.kering import ValidationError



class QueryEnd:
    """Serve verified history only with an exact current-source observation."""
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
        observations = [record for url in self.ctx.urls
                        if (record := self.ctx.observations.observations.get((url,)))
                        and record.heads.get(regk) == self.ctx.store.head(regk).qb64]
        if not observations:
            raise falcon.HTTPServiceUnavailable(
                description='no completed observation for accepted head')
        completed = max(record.completed for record in observations)
        age = (helping.nowUTC() - helping.fromIso8601(completed)).total_seconds()
        if age < 0 or age > self.ctx.maximumAge:
            raise falcon.HTTPServiceUnavailable(
                description='cached observation is stale')
        try:
            rep.data = self.ctx.clone([regk], sn=sn)
        except ValidationError as ex:
            raise falcon.HTTPServiceUnavailable(
                description='registry history is outside the supported evidence profile') from ex
        rep.content_type = CESR_CONTENT_TYPE
        rep.set_header('Observer-Observed-At', completed)
        rep.set_header('Observer-Evidence-State', 'fresh')
        rep.set_header('Observer-Registry-Head', self.ctx.store.head(regk).qb64)
