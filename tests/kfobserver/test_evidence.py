"""Full-evidence service tests using real signed queries and core verification."""
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
import ssl

import falcon
import pytest
from falcon import testing
from hio.base import doing
from hio.core import http, tcp
from keri import Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.acdc.regbasing import RegBaser
from keri.app.evidencing import EvidenceContext, signedQuery
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Counter, Codens, Parser, SerderACDC
from keri.db import dbing, koming
from keri.help import helping

from kfobserver.core.evidence import Context
from kfobserver.core.evidence_observing import (
    Observation, ObservationBaser, RegistrarPuller, SourceTrust, sourceTrusts)


TLS_DIR = Path(__file__).parents[1] / 'tls'
SERVER_TLS = TLS_DIR / 'server.pem'
WRONG_TLS = TLS_DIR / 'client.pem'


@dataclass
class OldObservation:
    """The removed KERIpy adapter's persisted record shape."""
    completed: str = ''
    heads: dict = field(default_factory=dict)


class OldObservationBaser(dbing.LMDBer):
    """Write the pre-extraction schema without importing the retired adapter."""
    TailDirPath = 'keri/observer'
    AltTailDirPath = '.keri/observer'

    def reopen(self, **kwa):
        super().reopen(**kwa)
        self.observations = koming.Komer(
            db=self, subkey='observations.', klas=OldObservation)
        return self.opened


def trust(url, *, ca=SERVER_TLS, certedhost=None):
    """Return explicit source trust for the loopback TLS fixtures."""
    return dict(url=url, cafilepath=str(ca), certedhost=certedhost)


def tlsServer(raw, certificate=SERVER_TLS, requests=None):
    """Serve one copied public evidence body through a real HIO TLS listener."""
    class Bulk:
        def on_post(self, req, rep):
            if requests is not None:
                requests.append(req.path)
            rep.data = raw
            rep.content_type = CESR_CONTENT_TYPE

    app = falcon.App()
    app.add_route('/', Bulk())
    servant = tcp.ServerTls(host='127.0.0.1', port=0,
        keypath=str(certificate), certpath=str(certificate), certify=ssl.CERT_NONE)
    server = http.Server(servant=servant, app=app)
    assert server.reopen()
    server.servant.eha = server.servant.ha
    return server


def issuedEvidence(hab):
    """Create a KEL-anchored registry stream and return its accepted head."""
    rip = regcept(israid=hab.pre)
    credential = acdcmap(israid=hab.pre, regid=rip.said,
                         attribute={"d": "", "example": True})
    opening = Blinder.blind(acdc=credential.said, state='issued')
    bup = blindate(rip.said, rip.said, opening.said)
    hab.interact(data=[dict(s=e.sad["n"], d=e.said) for e in (rip, bup)])
    empty = Counter.enclose(qb64=b'', code=Codens.AttachmentGroup,
                            version=Vrsn_2_0)
    opened = Counter.enclose(qb64=Blinder.enclose([opening]),
                             code=Codens.AttachmentGroup, version=Vrsn_2_0)
    raw = hab.replay(gvrsn=Vrsn_2_0) + rip.raw + empty + bup.raw + opened
    return rip, bup, credential, raw


def publicEvidence(hab):
    """Create complete KEL/rip/public-bup evidence with the expanded opening."""
    rip = regcept(israid=hab.pre)
    credential = acdcmap(israid=hab.pre, regid=rip.said,
                         attribute={"d": "", "public": True})
    opening = Blinder.blind(acdc=credential.said, state='issued')
    bup = blindate(rip.said, rip.said, opening.said)
    hab.interact(data=[dict(s=e.sad['n'], d=e.said) for e in (rip, bup)])
    empty = Counter.enclose(qb64=b'', code=Codens.AttachmentGroup,
                            version=Vrsn_2_0)
    opened = Counter.enclose(qb64=Blinder.enclose([opening]),
                             code=Codens.AttachmentGroup, version=Vrsn_2_0)
    raw = hab.replay(gvrsn=Vrsn_2_0) + rip.raw + empty + bup.raw + opened
    return rip, bup, opening, raw


def publicOpening(raw, event):
    """Extract the sole opening attached to one event in a full evidence stream."""
    remaining = bytearray(raw)
    parser = Parser(version=Vrsn_2_0)
    found = []
    while remaining:
        dom = parser.parseOne(ims=remaining, processive=False, local=False)
        if isinstance(dom.serder, SerderACDC) and dom.serder.said == event.said:
            found.extend(dom.bsqs)
            found.extend(dom.bsss)
    assert len(found) == 1
    return b''.join(item.qb64b for item in found[0])


def test_cache_queries_require_current_source_and_exact_observed_head():
    """Reject unknown, unobserved, obsolete-source and stale cache answers."""
    with (openHby(name="source", version=Vrsn_2_0) as issuer,
          openHby(name="observer", version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name="issuer")
        reader = receiver.makeHab(name="reader")
        rip, bup, credential, raw = issuedEvidence(controller)
        url = "https://independent-source/"
        ctx = Context(receiver, readers=[reader.pre], sources=[trust(url)], maximumAge=3)
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
            assert not ctx.observe("https://obsolete-source/", raw)["rejected"]
            assert request().status_code == 503
            assert not ctx.observe(url, raw)["rejected"]
            response = request()
            assert response.status_code == 200
            assert response.headers["observer-registry-head"] == bup.said
            # Historical accepted evidence remains intact, but an expired
            # receiver observation cannot authorize a fresh cache response.
            old = helping.toIso8601(helping.nowUTC() - timedelta(seconds=30))
            ctx.observations.observations.pin((url,), Observation(old, {rip.said: bup.said}))
            assert request().status_code == 503
            assert ctx.store.headEvent(rip.said).said == bup.said
            assert not ctx.observe(url, raw)["rejected"]
            opening = Blinder.blind(acdc=credential.said, state='revoked')
            revoked = blindate(rip.said, bup.said, opening.said, sn=2)
            controller.interact(data=[dict(s=revoked.sad["n"], d=revoked.said)])
            opened = Counter.enclose(qb64=Blinder.enclose([opening]),
                code=Codens.AttachmentGroup, version=Vrsn_2_0)
            assert not ctx.ingest(controller.replay(gvrsn=Vrsn_2_0)
                                  + revoked.raw + opened)["rejected"]
            assert request().status_code == 503  # old observation names the former head
        finally:
            ctx.close()


def test_public_bup_opening_survives_observer_requery_and_store_reopen(tmp_path):
    """Serve the exact accepted opening after observation, downstream ingest, and reopen."""
    with (openHby(name='opening-source', version=Vrsn_2_0) as issuer,
          openHby(name='opening-observer', version=Vrsn_2_0) as receiver,
          openHby(name='opening-consumer', version=Vrsn_2_0) as consumer):
        controller = issuer.makeHab(name='issuer')
        reader = receiver.makeHab(name='reader')
        rip, bup, opening, raw = publicEvidence(controller)
        url = 'https://registrar.example/evidence'
        baser = RegBaser(name='opening-observer', headDirPath=str(tmp_path), temp=False)
        observations = ObservationBaser(
            name='opening-observer', headDirPath=str(tmp_path), temp=False)
        first = Context(receiver, readers=[reader.pre], sources=[trust(url)],
                        reger=baser, observations=observations, maximumAge=30)
        independent = EvidenceContext(consumer)
        try:
            assert not first.observe(url, raw)['rejected']
            response = testing.TestClient(first.app).simulate_post(
                '/', headers={'Content-Type': CESR_CONTENT_TYPE},
                body=signedQuery(reader, 'tels', {'i': rip.said}))
            assert response.status_code == 200
            assert publicOpening(response.content, bup) == opening.qb64b
            result = independent.ingest(response.content)
            assert not result['pending'] and not result['rejected']
            assert independent.store.opening(bup.said) == opening.qb64
        finally:
            independent.close()
            first.close()

        baser.reopen()
        observations.reopen()
        second = Context(receiver, readers=[reader.pre], sources=[trust(url)],
                         reger=baser, observations=observations, maximumAge=30)
        try:
            response = testing.TestClient(second.app).simulate_post(
                '/', headers={'Content-Type': CESR_CONTENT_TYPE},
                body=signedQuery(reader, 'tels', {'i': rip.said}))
            assert response.status_code == 200
            assert publicOpening(response.content, bup) == opening.qb64b
        finally:
            second.close()


def test_old_producer_new_consumer_reopens_observation_schema(tmp_path):
    """Read legacy KERIpy rows through the app-owned unchanged LMDB contract."""
    url = 'https://registrar.example/evidence'
    old = OldObservationBaser(name='compat', headDirPath=str(tmp_path), temp=False)
    old.observations.pin((url,), OldObservation('2026-10-24T00:00:00.000000+00:00',
                                                {'registry': 'head'}))
    old.close()

    new = ObservationBaser(name='compat', headDirPath=str(tmp_path), temp=False)
    try:
        record = new.observations.get((url,))
        assert record == Observation('2026-10-24T00:00:00.000000+00:00',
                                     {'registry': 'head'})
        assert new.TailDirPath == 'keri/observer'
    finally:
        new.close()


@pytest.mark.parametrize('config, message', [
    ({'url': 'http://registrar.example/', 'cafilepath': str(SERVER_TLS)}, 'HTTPS'),
    ({'url': 'https://registrar.example/', 'cafilepath': str(SERVER_TLS),
      'certedhost': 'other.example'}, 'IP URL'),
    ({'url': 'https://127.0.0.1/', 'cafilepath': str(SERVER_TLS)}, 'explicit'),
    ({'url': 'https://registrar.example/', 'cafilepath': 'relative.pem'}, 'absolute'),
])
def test_source_trust_fails_closed(config, message):
    """Reject unauthenticated and ambiguous full-evidence source configuration."""
    with pytest.raises(ValueError, match=message):
        SourceTrust.fromConfig(config)


def test_source_trust_ip_mapping_is_explicit_and_complete():
    """Map only configured IP connectors and leave DNS identity to its URL."""
    source = sourceTrusts(['https://127.0.0.1:4443/tels'],
        cafilepath=str(SERVER_TLS), certedhosts=['127.0.0.1=localhost'])[0]
    assert source.certedhost == 'localhost'
    with pytest.raises(ValueError, match='no configured IP source'):
        sourceTrusts(['https://registrar.example/'], cafilepath=str(SERVER_TLS),
                     certedhosts=['127.0.0.1=localhost'])


def test_real_https_source_records_exact_url_observation():
    """Accept evidence only after HIO verifies the configured CA and hostname."""
    with (openHby(name='tls-source', version=Vrsn_2_0) as issuer,
          openHby(name='tls-observer', version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='issuer')
        requester = receiver.makeHab(name='observer')
        rip, bup, _, raw = issuedEvidence(controller)
        requests = []
        server = tlsServer(raw, requests=requests)
        url = f'https://127.0.0.1:{server.servant.ha[1]}/'
        source = SourceTrust.fromConfig(trust(url, certedhost='localhost'))
        ctx = Context(receiver, readers=[requester.pre], sources=[source], maximumAge=3)
        puller = RegistrarPuller(requester, ctx, [source], interval=10, timeout=1)
        try:
            doing.Doist(real=True, tock=0.01, limit=0.7).do(
                doers=[http.ServerDoer(server=server), puller])
            record = ctx.observations.observations.get((url,))
            assert requests == ['/']
            assert record.heads[rip.said] == bup.said
            assert puller.results[-1][0] == url
        finally:
            server.close()
            ctx.close()


@pytest.mark.parametrize('ca, certedhost', [
    (WRONG_TLS, 'localhost'),
    (SERVER_TLS, 'wrong.example'),
])
def test_wrong_source_ca_or_hostname_records_no_freshness(ca, certedhost):
    """Contain real TLS failures and leave the source observation absent."""
    with (openHby(name='bad-tls-source', version=Vrsn_2_0) as issuer,
          openHby(name='bad-tls-observer', version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='issuer')
        requester = receiver.makeHab(name='observer')
        _, _, _, raw = issuedEvidence(controller)
        requests = []
        server = tlsServer(raw, requests=requests)
        url = f'https://127.0.0.1:{server.servant.ha[1]}/'
        source = SourceTrust.fromConfig(trust(url, ca=ca, certedhost=certedhost))
        ctx = Context(receiver, readers=[requester.pre], sources=[source])
        puller = RegistrarPuller(requester, ctx, [source], interval=10, timeout=.3)
        try:
            doing.Doist(real=True, tock=0.01, limit=0.5).do(
                doers=[http.ServerDoer(server=server), puller])
            assert ctx.observations.observations.get((url,)) is None
            assert requests == []
            assert 'transport_error' in puller.results[-1][1]
            assert puller.client is None
        finally:
            server.close()
            ctx.close()


def test_replayed_body_under_wrong_identity_does_not_stop_later_source():
    """Reject a copied response at the TLS identity boundary and keep polling."""
    with (openHby(name='identity-source', version=Vrsn_2_0) as issuer,
          openHby(name='identity-observer', version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='issuer')
        requester = receiver.makeHab(name='observer')
        rip, bup, _, raw = issuedEvidence(controller)
        impostorRequests, authenticRequests = [], []
        impostor = tlsServer(raw, certificate=WRONG_TLS, requests=impostorRequests)
        authentic = tlsServer(raw, certificate=SERVER_TLS, requests=authenticRequests)
        badUrl = f'https://127.0.0.1:{impostor.servant.ha[1]}/'
        goodUrl = f'https://127.0.0.1:{authentic.servant.ha[1]}/'
        sources = [SourceTrust.fromConfig(trust(url, certedhost='localhost'))
                   for url in (badUrl, goodUrl)]
        ctx = Context(receiver, readers=[requester.pre], sources=sources)
        puller = RegistrarPuller(requester, ctx, sources, interval=10, timeout=.5)
        try:
            doing.Doist(real=True, tock=0.01, limit=1).do(doers=[
                http.ServerDoer(server=impostor), http.ServerDoer(server=authentic), puller])
            assert impostorRequests == []
            assert ctx.observations.observations.get((badUrl,)) is None
            assert authenticRequests == ['/']
            assert ctx.observations.observations.get((goodUrl,)).heads[rip.said] == bup.said
            assert puller.results[0][0] == badUrl
            assert 'transport_error' in puller.results[0][1]
            assert puller.results[1][0] == goodUrl
        finally:
            impostor.close()
            authentic.close()
            ctx.close()


@pytest.mark.parametrize('failure', ['setup', 'malformed-response'])
def test_failed_source_request_does_not_stop_later_source(monkeypatch, failure):
    """A client setup or parser failure must not block another trusted source."""
    with (openHby(name='failed-source-issuer', temp=True, version=Vrsn_2_0) as issuer,
          openHby(name='failed-source-observer', temp=True, version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='issuer')
        requester = receiver.makeHab(name='observer')
        rip, bup, _, raw = issuedEvidence(controller)
        first = tlsServer(raw)
        second = tlsServer(raw)
        badUrl = f'https://127.0.0.1:{first.servant.ha[1]}/'
        goodUrl = f'https://127.0.0.1:{second.servant.ha[1]}/'
        sources = [SourceTrust.fromConfig(trust(url, certedhost='localhost'))
                   for url in (badUrl, goodUrl)]
        ctx = Context(receiver, readers=[requester.pre], sources=sources)
        puller = RegistrarPuller(requester, ctx, sources, interval=10, timeout=.5)
        realClient = http.clienting.Client

        def client(*args, **kwa):
            if kwa.get('port') == first.servant.ha[1]:
                if failure == 'setup':
                    raise OSError('source setup failed')
                result = realClient(*args, **kwa)

                def malformed():
                    raise ValueError('malformed HTTP response')

                result.service = malformed
                return result
            return realClient(*args, **kwa)

        monkeypatch.setattr(http.clienting, 'Client', client)
        try:
            doing.Doist(real=True, tock=.01, limit=.8).do(doers=[
                http.ServerDoer(server=first), http.ServerDoer(server=second), puller])
            assert 'transport_error' in puller.results[0][1]
            assert puller.results[0][0] == badUrl
            assert puller.results[1][0] == goodUrl
            assert ctx.observations.observations.get((goodUrl,)).heads[rip.said] == bup.said
            assert ctx.observations.observations.get((badUrl,)) is None
            assert puller.client is None
        finally:
            first.close()
            second.close()
            ctx.close()


def test_source_rotation_requires_a_new_completed_observation(tmp_path):
    """Persist old evidence while refusing to treat an old source as current."""
    oldUrl = 'https://registrar-old.example/evidence'
    newUrl = 'https://registrar-new.example/evidence'
    with openHby(name='rotation-source', version=Vrsn_2_0) as issuer, \
            openHby(name='rotation-observer', headDirPath=str(tmp_path),
                    temp=False, version=Vrsn_2_0) as receiver:
        controller = issuer.makeHab(name='issuer')
        reader = receiver.makeHab(name='reader')
        rip, upd, _, raw = issuedEvidence(controller)

        def context(sources):
            return Context(
                receiver,
                readers=[reader.pre],
                sources=[trust(url) for url in sources],
                reger=RegBaser(
                    name='rotation', headDirPath=str(tmp_path), temp=False),
                observations=ObservationBaser(
                    name='rotation', headDirPath=str(tmp_path), temp=False),
            )

        first = context([oldUrl])
        try:
            assert not first.observe(oldUrl, raw)['rejected']
            old = first.observations.observations.get((oldUrl,))
            assert old.heads == {rip.said: upd.said}
        finally:
            first.close()

        second = context([newUrl])
        try:
            client = testing.TestClient(second.app)

            def request():
                return client.simulate_post(
                    '/', headers={'Content-Type': CESR_CONTENT_TYPE},
                    body=signedQuery(reader, 'tels', {'i': rip.said}))

            assert second.store.headEvent(rip.said).said == upd.said
            assert second.observations.observations.get((oldUrl,)) == old
            assert request().status_code == 503
            assert not second.observe(oldUrl, raw)['rejected']
            assert second.observations.observations.get((oldUrl,)) == old
            assert request().status_code == 503
            assert not second.observe(newUrl, raw)['rejected']
            assert request().status_code == 200
        finally:
            second.close()


def test_pending_evidence_reopens_without_claiming_freshness(tmp_path):
    """Recover accepted TEL state after KEL arrival without inventing an observation."""
    url = 'https://registrar.example/evidence'
    with openHby(name='pending-source', version=Vrsn_2_0) as issuer, \
            openHby(name='pending-observer', headDirPath=str(tmp_path),
                    temp=False, version=Vrsn_2_0) as receiver:
        controller = issuer.makeHab(name='issuer')
        reader = receiver.makeHab(name='reader')
        rip, upd, _, raw = issuedEvidence(controller)
        tel = raw[len(controller.replay(gvrsn=Vrsn_2_0)):]

        def context():
            return Context(
                receiver,
                readers=[reader.pre],
                sources=[trust(url)],
                reger=RegBaser(
                    name='pending', headDirPath=str(tmp_path), temp=False),
                observations=ObservationBaser(
                    name='pending', headDirPath=str(tmp_path), temp=False),
            )

        first = context()
        try:
            result = first.observe(url, tel)
            assert result['pending'] and not result['accepted']
            assert first.observations.observations.get((url,)) is None
        finally:
            first.close()

        second = context()
        try:
            assert not second.ingest(controller.replay(gvrsn=Vrsn_2_0))['rejected']
            assert second.store.headEvent(rip.said).said == upd.said
            assert second.observations.observations.get((url,)) is None
            response = testing.TestClient(second.app).simulate_post(
                '/', headers={'Content-Type': CESR_CONTENT_TYPE},
                body=signedQuery(reader, 'tels', {'i': rip.said}))
            assert response.status_code == 503
        finally:
            second.close()


@pytest.mark.parametrize('value', [0, -1, float('nan'), float('inf')])
def test_observation_durations_must_be_finite_and_positive(value):
    """Reject invalid freshness and polling limits before scheduling work."""
    with openHby(name='duration-observer', version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name='observer')
        with pytest.raises(ValueError):
            Context(hby, maximumAge=value)
        ctx = Context(hby)
        try:
            with pytest.raises(ValueError):
                RegistrarPuller(hab, ctx, (), interval=value)
            with pytest.raises(ValueError):
                RegistrarPuller(hab, ctx, (), timeout=value)
        finally:
            ctx.close()


def test_full_evidence_pruner_survives_restart_and_cancellation(tmp_path, monkeypatch):
    """Expire authenticated query state without deleting verified KEL evidence."""
    now = [helping.fromIso8601('2021-01-01T00:00:00.000000+00:00')]
    monkeypatch.setattr(helping, 'nowUTC', lambda: now[0])
    monkeypatch.setattr(helping, 'nowIso8601', lambda: helping.toIso8601(now[0]))

    config = {'kram': {'enabled': True, 'denials': [],
              'caches': {'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}
    with openHby(name='pruner-source', version=Vrsn_2_0) as sender:
        hab = sender.makeHab(name='sender')
        raw = signedQuery(hab, 'tels', {'i': hab.pre})
        query = Parser(version=Vrsn_2_0).parseOne(
            ims=bytearray(raw), processive=False).serder
        key = (hab.pre, query.said)

        with openHby(name='pruner-observer', headDirPath=str(tmp_path),
                     temp=False, version=Vrsn_2_0) as receiver:
            ctx = Context(receiver, readers=[hab.pre], config=config)
            try:
                assert not ctx.ingest(hab.replay(gvrsn=Vrsn_2_0))['rejected']
                response = testing.TestClient(ctx.app).simulate_post(
                    '/', body=raw, headers={'Content-Type': CESR_CONTENT_TYPE})
                assert response.status_code == 404
                cached = receiver.db.kramMSGC.get(key)
                assert cached is not None
                doist = doing.Doist(tock=1.0)
                deeds = doist.enter(doers=[ctx])
                doist.recur(deeds=deeds)
                doist.exit(deeds=deeds)
                assert receiver.db.kramMSGC.get(key) == cached
            finally:
                ctx.close()

        now[0] += timedelta(milliseconds=cached.d + cached.pml + 1)
        with openHby(name='pruner-observer', headDirPath=str(tmp_path),
                     temp=False, version=Vrsn_2_0) as receiver:
            ctx = Context(receiver, readers=[hab.pre], config=config)
            deeds = None
            try:
                assert ctx.pruner.kramer is ctx.kvy.kramer
                assert ctx.doers.count(ctx.pruner) == 1
                doist = doing.Doist(tock=1.0)
                deeds = doist.enter(doers=[ctx])
                doist.recur(deeds=deeds)
                assert receiver.db.kramMSGC.get(key) is None
                assert receiver.db.kels.getLast(
                    keys=hab.pre, on=0) == hab.kever.serder.said
                response = testing.TestClient(ctx.app).simulate_post(
                    '/', body=raw, headers={'Content-Type': CESR_CONTENT_TYPE})
                assert response.status_code == 401
            finally:
                if deeds is not None:
                    doist.exit(deeds=deeds)
                ctx.close()
