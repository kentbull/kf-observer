# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_serving module

HTTP face tests for wallet/verifier verified-TEL queries.
"""

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp
from falcon import testing

from keri import Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Parser, SerderACDC, query
from keri.core.signing import Salter
from keri.help import helping

from kfobserver.core.serving import makeContext


STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
SALT = Salter(raw=b"0123456789abcdef").qb64


def seal(serder):
    return dict(s=serder.sad["n"], d=serder.said)


def anchor(hab, *serders):
    hab.interact(data=[seal(serder) for serder in serders])


def telStream(*serders):
    stream = bytearray()
    for serder in serders:
        stream.extend(serder.raw)
    return bytes(stream)


def _postCesr(client, hab, serder, path="/"):
    msg = hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0)
    headers = {"Content-Type": CESR_CONTENT_TYPE}
    return client.simulate_post(path, body=bytes(msg), headers=headers)


def _telQuery(hab, regk, route="tels", **qextra):
    q = dict(i=regk, **qextra)
    return query(
        pre=hab.pre,
        route=route,
        query=q,
        stamp=helping.nowIso8601(),
        version=Vrsn_2_0,
    )


def _telIlks(raw):
    ims = bytearray(raw)
    ilks = []
    while ims:
        serder = SerderACDC(raw=ims)
        ilks.append(serder.ilk)
        del ims[: serder.size]
    return ilks


def _seedObserverTel(hby, issuer):
    ripper = regcept(israid=issuer.pre, stamp=STAMP0)
    anchor(issuer, ripper)
    acdc = acdcmap(
        israid=issuer.pre,
        regid=ripper.said,
        attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
        iseaid=issuer.pre,
    )
    blinder = Blinder.blind(acdc=acdc.said, state="issued", salt=SALT, sn=1)
    bup = blindate(
        regid=ripper.said,
        prior=ripper.said,
        blid=blinder.said,
        sn=1,
        stamp=STAMP1,
    )
    anchor(issuer, bup)
    return ripper, bup, blinder, acdc, telStream(ripper, bup)


def test_wallet_query_last_all_since_sn():
    """Signed tels / tels/head queries return verified CESR only."""
    with openHby(name="kf-obs-http", base="test", temp=True, version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer")
        observerHab = hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        ripper, bup, _blinder, _acdc, stream = _seedObserverTel(hby, issuer)

        ctx = makeContext(hby=hby, alias="observer")
        try:
            summary = ctx.observer.ingest(stream)
            assert ripper.said in summary["accepted"]

            client = testing.TestClient(ctx.app)

            allQry = _telQuery(wallet, ripper.said, route="tels")
            allResp = _postCesr(client, wallet, allQry)
            assert allResp.status == falcon.HTTP_200
            assert allResp.headers["content-type"] == CESR_CONTENT_TYPE
            assert allResp.content == stream
            assert _telIlks(allResp.content) == ["rip", "bup"]

            sinceQry = _telQuery(wallet, ripper.said, route="tels", sn=1)
            sinceResp = _postCesr(client, wallet, sinceQry)
            assert sinceResp.status == falcon.HTTP_200
            assert sinceResp.content == bytes(bup.raw)

            headQry = _telQuery(wallet, ripper.said, route="tels/head")
            headResp = _postCesr(client, wallet, headQry)
            assert headResp.status == falcon.HTTP_200
            assert headResp.content == bytes(bup.raw)

            missing = _telQuery(wallet, "E" + "B" * 43, route="tels")
            missingResp = _postCesr(client, wallet, missing)
            assert missingResp.status == falcon.HTTP_404

            bulk = _telQuery(wallet, ripper.said, route="tels/bulk")
            bulkResp = _postCesr(client, wallet, bulk)
            assert bulkResp.status == falcon.HTTP_403

            # unused but proves observer hab exists for ops
            assert observerHab.pre == ctx.hab.pre
        finally:
            ctx.observer.close()


def test_health():
    """Liveness probe leaks no TEL."""
    with openHby(name="kf-obs-health", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="observer")
        ctx = makeContext(hby=hby, alias="observer")
        try:
            client = testing.TestClient(ctx.app)
            response = client.simulate_get("/health")
            assert response.status == falcon.HTTP_200
            assert response.json["status"] == "ok"
        finally:
            ctx.observer.close()


@pytest.mark.parametrize(
    ("outcome", "route", "qextra", "status"),
    [
        ("success", "tels", {}, 200),
        ("success", "tels", {"sn": 1}, 200),
        ("success", "tels/head", {}, 200),
        ("pending", "tels", {}, 503),
        ("missing", "tels", {}, 404),
        ("http-failure", "tels", {}, 404),
        ("malformed", "tels", {}, 404),
        ("timeout", "tels", {}, 404),
        ("success", "tels", {"sn": "bad-number"}, 500),
        ("success", "tels", {"sn": []}, 500),
        ("success", "tels", {"sn": {}}, 500),
        ("missing", "tels", {"sn": "bad-number"}, 404),
        ("pending", "tels", {"sn": "bad-number"}, 503),
        ("missing", "tels", {"sn": []}, 404),
        ("pending", "tels", {"sn": {}}, 503),
        ("cancel", "tels", {}, None),
    ],
)
def test_ondemand_query_returns_same_request_without_stalling_scheduler(
    monkeypatch, outcome, route, qextra, status
):
    """Real signed query, backend HTTP, scheduler progress and deferred status."""
    doist = doing.Doist(tock=0.03125, real=False)
    progress = []
    backendTurns = []
    pulled = []
    closed = []
    malformed = []
    originalService = http.clienting.Client.service
    originalClose = http.clienting.Client.close

    def independentDo(tymth=None, tock=0.0, **kwa):
        while True:
            progress.append(tymth())
            yield tock

    def service(client):
        if client.connector.port == registrar.servant.ha[1]:
            backendTurns.append(len(progress))
            if outcome == "malformed" and not malformed:
                malformed.append(client)
                client.connector.serviceReceives = lambda: None
                client.connector.rxbs.extend(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nG\r\n"
                )
        originalService(client)

    def close(client):
        if client.connector.port == registrar.servant.ha[1]:
            closed.append(client)
        originalClose(client)

    monkeypatch.setattr(http.clienting.Client, "service", service)
    monkeypatch.setattr(http.clienting.Client, "close", close)

    with openHby(
        name="kf-obs-query-coop", base="test", temp=True, version=Vrsn_2_0
    ) as hby:
        issuer = hby.makeHab(name="issuer")
        hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        if outcome == "pending":
            ripper = regcept(israid=issuer.pre, stamp=STAMP0)
            stream = telStream(ripper)
            bulk = stream  # Deliberately unanchored.
        else:
            ripper, bup, _blinder, _acdc, stream = _seedObserverTel(hby, issuer)
            kel = b"".join(issuer.db.clonePreIter(pre=issuer.pre, gvrsn=Vrsn_2_0))
            bulk = kel + stream

        class RegistrarEnd:
            def on_post(self, req, rep):
                raw = req.bounded_stream.read()
                dom = Parser(version=Vrsn_2_0).parseOne(
                    ims=bytearray(raw), framed=True, processive=False
                )
                assert dom.serder.ked["r"] == "tels/bulk"
                assert dom.serder.ked["i"] == ctx.hab.pre
                assert dom.serder.ked["q"] == {"i": ripper.said}
                assert dom.serder.pvrsn == Vrsn_2_0
                assert raw == bytes(
                    ctx.hab.endorse(dom.serder, last=True, framed=False, gvrsn=Vrsn_2_0)
                )
                assert req.content_type == CESR_CONTENT_TYPE
                pulled.append(doist.tyme)
                if outcome == "http-failure":
                    rep.status = falcon.HTTP_503

                def delayed():
                    if outcome == "timeout":
                        while True:
                            yield b""
                    for _ in range(4):
                        yield b""
                    yield bulk if outcome not in ("missing", "http-failure") else b""

                rep.stream = delayed()

        peer = falcon.App()
        peer.add_route("/", RegistrarEnd())
        with http.serving.openServer(
            servant=tcp.Server(ha=("127.0.0.1", 0)), app=peer
        ) as registrar:
            registrar.servant.eha = registrar.servant.ha
            ctx = makeContext(
                hby=hby,
                alias="observer",
                registrars=[f"http://127.0.0.1:{registrar.servant.ha[1]}/"],
            )
            try:
                with http.serving.openServer(
                    servant=tcp.Server(ha=("127.0.0.1", 0)), app=ctx.app
                ) as observerServer:
                    observerServer.servant.eha = observerServer.servant.ha
                    client = http.clienting.Client(
                        hostname="127.0.0.1", port=observerServer.servant.ha[1]
                    )
                    qry = _telQuery(wallet, ripper.said, route=route, **qextra)
                    body = bytes(
                        wallet.endorse(qry, last=True, framed=False, gvrsn=Vrsn_2_0)
                    )
                    client.request(
                        method="POST",
                        path="/",
                        body=body,
                        headers={"Content-Type": CESR_CONTENT_TYPE},
                    )
                    doist.deeds = doist.enter(
                        doers=[
                            ctx,
                            http.ServerDoer(registrar),
                            http.ServerDoer(observerServer),
                            http.ClientDoer(client),
                            doing.doify(independentDo),
                        ]
                    )
                    try:
                        assert not ctx.observer.hasRegistry(ripper.said)
                        for _ in range(400):
                            doist.recur()
                            if outcome == "cancel" and len(set(backendTurns)) >= 2:
                                responder = next(iter(observerServer.reps.values()))
                                assert not responder.headed
                                responder.iterator.close()
                                assert len(closed) == 1
                                assert closed[0].connector.cs is None
                                return
                            if client.responses:
                                break
                        response = client.respond()
                        assert response is not None
                        assert response.status == status
                        assert len(pulled) == (0 if outcome == "malformed" else 1)
                        assert len(set(backendTurns)) >= (
                            1 if outcome == "malformed" else 4
                        )
                        assert len(closed) == 1
                        assert closed[0].connector.cs is None
                        if outcome == "malformed":
                            assert len(malformed) == 1
                        if outcome == "success" and status == 200:
                            assert response.headers["content-type"] == CESR_CONTENT_TYPE
                            assert bytes(response.body) == (
                                bytes(bup.raw)
                                if qextra or route == "tels/head"
                                else stream
                            )
                            fresh = _telQuery(
                                wallet, ripper.said, route=route, **qextra
                            )
                            body = bytes(
                                wallet.endorse(
                                    fresh, last=True, framed=False, gvrsn=Vrsn_2_0
                                )
                            )
                            client.request(
                                method="POST",
                                path="/",
                                body=body,
                                headers={"Content-Type": CESR_CONTENT_TYPE},
                            )
                            for _ in range(100):
                                doist.recur()
                                if client.responses:
                                    break
                            assert client.respond().status == 200
                            assert len(pulled) == 1  # Now served from the local store.
                        else:
                            assert (
                                response.headers["content-type"] == "application/json"
                            )
                            assert (ripper.said in ctx.observer.pending) == (
                                outcome == "pending"
                            )
                            if outcome == "success":
                                fresh = _telQuery(wallet, ripper.said, **qextra)
                                body = bytes(
                                    wallet.endorse(
                                        fresh, last=True, framed=False, gvrsn=Vrsn_2_0
                                    )
                                )
                                client.request(
                                    method="POST",
                                    path="/",
                                    body=body,
                                    headers={"Content-Type": CESR_CONTENT_TYPE},
                                )
                                for _ in range(100):
                                    doist.recur()
                                    if client.responses:
                                        break
                                assert client.respond().status == 500
                                assert len(pulled) == 1
                    finally:
                        doist.exit()
            finally:
                ctx.observer.close()
