"""Native TEL guarantees retained from the retired second acceptance engine."""
from falcon import testing
from keri import Vrsn_2_0
from keri.acdc import blindate
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Codens, Counter
from kfobserver.core.evidence import Context
from .test_evidence import issuedEvidence, trust
from kfobserver.core.evidence_observing import signedQuery


def frame(*events):
    empty = Counter.enclose(qb64=b'', code=Codens.AttachmentGroup, version=Vrsn_2_0)
    return b''.join(event.raw + empty for event in events)


def anchor(hab, regid, event):
    hab.interact(data=[dict(i=regid, s=event.sad['n'], d=event.said)])


def test_native_ordering_replay_conflict_and_forward_progress():
    """Independent intake never replaces accepted slots or regresses the head."""
    with (openHby(name='ordering-source', version=Vrsn_2_0) as source,
          openHby(name='ordering-cache', version=Vrsn_2_0) as receiver):
        issuer = source.makeHab(name='issuer')
        rip, first, credential, raw = issuedEvidence(issuer)
        opening = Blinder.blind(acdc=credential.said, state='revoked')
        second = blindate(rip.said, first.said, opening.said, sn=2)
        anchor(issuer, rip.said, second)
        ctx = Context(receiver)
        try:
            assert not ctx.ingest(issuer.replay(gvrsn=Vrsn_2_0))['rejected']
            pending = ctx.ingest(frame(rip, second))
            assert pending['pending'][rip.said] == 1
            assert ctx.store.headEvent(rip.said).said == rip.said
            assert ctx.ingest(frame(first))['accepted'][rip.said] == 1
            assert ctx.store.seqEvent(rip.said, 1).said == first.said
            assert ctx.store.headEvent(rip.said).said == second.said
            assert not ctx.ingest(raw)['rejected']
            assert ctx.store.headEvent(rip.said).said == second.said
            rivalOpening = Blinder.blind(acdc=credential.said, state='other')
            rival = blindate(rip.said, rip.said, rivalOpening.said)
            anchor(issuer, rip.said, rival)
            assert not ctx.ingest(issuer.replay(gvrsn=Vrsn_2_0))['rejected']
            assert ctx.ingest(frame(rival))['rejected']
            assert ctx.store.seqEvent(rip.said, 1).said == first.said
            assert ctx.store.headEvent(rip.said).said == second.said
            third = blindate(rip.said, second.said, opening.said, sn=3)
            anchor(issuer, rip.said, third)
            assert not ctx.ingest(issuer.replay(gvrsn=Vrsn_2_0) + frame(third))['rejected']
            assert ctx.store.headEvent(rip.said).said == third.said
        finally:
            ctx.close()


def test_tampered_body_is_not_accepted_and_retry_uses_real_source_evidence():
    with (openHby(name='tamper-source', version=Vrsn_2_0) as source,
          openHby(name='tamper-cache', version=Vrsn_2_0) as receiver):
        issuer = source.makeHab(name='issuer')
        reader = receiver.makeHab(name='reader')
        rip, bup, _, raw = issuedEvidence(issuer)
        ctx = Context(receiver, readers=[reader.pre])
        try:
            # Preserve the original body SAID while modifying its prior digest.
            bad = bup.raw.replace(rip.said.encode(), ('E' + 'A' * 43).encode(), 1)
            assert bad != bup.raw
            assert ctx.ingest(issuer.replay(gvrsn=Vrsn_2_0) + bad)['rejected']
            assert ctx.store.head(rip.said) is None
            assert not ctx.ingest(raw)['rejected']
            response = testing.TestClient(ctx.app).simulate_post('/',
                headers={'Content-Type': CESR_CONTENT_TYPE},
                body=signedQuery(reader, 'tels', {'i': rip.said}))
            assert response.status_code == 200
            assert ctx.store.headEvent(rip.said).said == bup.said
        finally:
            ctx.close()


def test_acquisition_heads_are_exact_to_the_returned_source_not_other_cache_heads():
    with (openHby(name='scope-source', version=Vrsn_2_0) as source,
          openHby(name='scope-cache', version=Vrsn_2_0) as receiver):
        issuer = source.makeHab(name='issuer')
        rip, first, credential, raw = issuedEvidence(issuer)
        urls = ('https://source-a.example/', 'https://source-b.example/')
        ctx = Context(receiver, sources=[trust(url) for url in urls])
        try:
            assert not ctx.observe(urls[0], raw)['pending']
            earlier = ctx.observations.observations.get((urls[0],))
            opening = Blinder.blind(acdc=credential.said, state='revoked')
            second = blindate(rip.said, first.said, opening.said, sn=2)
            anchor(issuer, rip.said, second)
            complete = issuer.replay(gvrsn=Vrsn_2_0) + frame(rip, first, second)
            assert not ctx.observe(urls[1], complete)['pending']
            assert ctx.store.headEvent(rip.said).said == second.said
            stale = ctx.observe(urls[0], raw)
            assert stale['heads'] == {rip.said: first.said}
            assert ctx.observations.observations.get((urls[0],)) == earlier
            assert ctx.observations.observations.get((urls[1],)).heads == {rip.said: second.said}
        finally:
            ctx.close()
