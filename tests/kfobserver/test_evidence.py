"""Full-evidence service tests using real signed queries and core verification."""
from datetime import timedelta

from falcon import testing
from keri import Vrsn_2_0
from keri.acdc import acdcmap, regcept, update
from keri.app.evidencing import signedQuery
from keri.app.evidence_observing import Observation
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Counter, Codens
from keri.help import helping

from kfobserver.core.evidence import Context


def test_cache_queries_require_current_source_and_exact_observed_head():
    """Reject unknown, unobserved, obsolete-source and stale cache answers."""
    with (openHby(name="source", version=Vrsn_2_0) as issuer,
          openHby(name="observer", version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name="issuer")
        reader = receiver.makeHab(name="reader")
        rip = regcept(israid=controller.pre)
        credential = acdcmap(israid=controller.pre, regid=rip.said,
                             attribute={"d": "", "example": True})
        upd = update(rip.said, rip.said, credential.said, "issued")
        controller.interact(data=[dict(s=e.sad["n"], d=e.said) for e in (rip, upd)])
        foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
        raw = controller.replay(gvrsn=Vrsn_2_0) + rip.raw + foot + upd.raw + foot
        url = "http://independent-source/"
        ctx = Context(receiver, readers=[reader.pre], urls=[url], maximumAge=3)
        try:
            client = testing.TestClient(ctx.app)

            def request():
                """Make a fresh authentic request without scheduling a source pull."""
                return client.simulate_post("/", headers={"Content-Type": CESR_CONTENT_TYPE},
                    body=signedQuery(reader, "tels", {"i": rip.said}))

            assert request().status_code == 404
            assert ctx.registries() == []
            assert not ctx.ingest(raw)["rejected"]
            assert request().status_code == 503
            assert not ctx.observe("http://obsolete-source/", raw)["rejected"]
            assert request().status_code == 503
            assert not ctx.observe(url, raw)["rejected"]
            response = request()
            assert response.status_code == 200
            assert response.headers["observer-registry-head"] == upd.said
            # Historical accepted evidence remains intact, but an expired
            # receiver observation cannot authorize a fresh cache response.
            old = helping.toIso8601(helping.nowUTC() - timedelta(seconds=30))
            ctx.observations.observations.pin((url,), Observation(old, {rip.said: upd.said}))
            assert request().status_code == 503
            assert ctx.store.headEvent(rip.said).said == upd.said
            assert not ctx.observe(url, raw)["rejected"]
            revoked = update(rip.said, upd.said, credential.said, "revoked", sn=2)
            controller.interact(data=[dict(s=revoked.sad["n"], d=revoked.said)])
            assert not ctx.ingest(controller.replay(gvrsn=Vrsn_2_0) + revoked.raw + foot)["rejected"]
            assert request().status_code == 503  # old observation names the former head
        finally:
            ctx.close()
