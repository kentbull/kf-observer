# -*- encoding: utf-8 -*-
"""
tests.kfobserver.test_serving module

HTTP face tests for wallet/verifier verified-TEL queries.
"""

from contextlib import ExitStack, contextmanager

import falcon
import pytest
from falcon import testing

from keri import Vrsn_1_0, Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Parser, SerderACDC, SerderKERI, eventing, query
from keri.core.coring import Diger
from keri.core.counting import Codens, Counter
from keri.core.signing import Salter
from keri.help import helping

from kfobserver.core.evidence import Context
from kfobserver.core.evidence_observing import ObservationBaser


STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
SALT = Salter(raw=b"0123456789abcdef").qb64


def seal(serder):
    return dict(i=serder.said if serder.ilk == "rip" else serder.sad["rd"],
                s=serder.sad["n"], d=serder.said)


def anchor(hab, *serders):
    hab.interact(data=[seal(serder) for serder in serders])


def telStream(*serders):
    stream = bytearray()
    for serder in serders:
        stream.extend(serder.raw)
        stream.extend(Counter.enclose(qb64=b"", code=Codens.AttachmentGroup, version=Vrsn_2_0))
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


def _telBodies(raw):
    ims = bytearray(raw)
    events = []
    parser = Parser(version=Vrsn_2_0)
    while ims:
        dom = parser.parseOneBare(ims=ims, processive=False)
        if isinstance(dom.serder, SerderACDC):
            events.append(dom.serder)
    return b"".join(event.raw for event in events)


def _telIlks(raw):
    ims = bytearray(_telBodies(raw))
    ilks = []
    while ims:
        event = SerderACDC(raw=ims)
        ilks.append(event.ilk)
        del ims[:event.size]
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


@contextmanager
def _remoteSignerLab(name, *, authorize=True, observations=None):
    """Keep registry issuer, query signer, and Observer in separate Haberies."""
    with ExitStack() as stack:
        issuerHby = stack.enter_context(
            openHby(name=f"{name}-issuer", base="test", temp=True, version=Vrsn_2_0)
        )
        signerHby = stack.enter_context(
            openHby(name=f"{name}-signer", base="test", temp=True, version=Vrsn_2_0)
        )
        observerHby = stack.enter_context(
            openHby(name=f"{name}-observer", base="test", temp=True, version=Vrsn_2_0)
        )
        issuer = issuerHby.makeHab(name="issuer")
        signer = signerHby.makeHab(name="wallet")
        observer = observerHby.makeHab(name="observer")
        ripper, bup, _blinder, _acdc, tel = _seedObserverTel(issuerHby, issuer)
        ctx = Context(observerHby, hab=observer, readers=[signer.pre] if authorize else [],
                      observations=observations)
        stack.callback(ctx.close)
        issuerKel = b"".join(issuer.db.clonePreIter(pre=issuer.pre, gvrsn=Vrsn_2_0))
        Parser(version=Vrsn_2_0).parse(ims=bytearray(issuerKel), kvy=ctx.kvy)
        assert ctx.ingest(tel)["accepted"]
        client = testing.TestClient(ctx.app)
        yield issuer, signer, observerHby, ctx, client, ripper.said, tel


def _signerKel(hab):
    return b"".join(hab.db.clonePreIter(pre=hab.pre, gvrsn=Vrsn_2_0))


def _putKel(client, raw, content_type=CESR_CONTENT_TYPE):
    headers = {"Content-Type": content_type} if content_type is not None else {}
    return client.simulate_put("/", body=raw, headers=headers)


def _signedTelQuery(client, hab, regk, endorser=None):
    qry = _telQuery(hab, regk)
    msg = (endorser or hab).endorse(qry, last=True, framed=False, gvrsn=Vrsn_2_0)
    return client.simulate_post(
        "/", body=bytes(msg), headers={"Content-Type": CESR_CONTENT_TYPE}
    )


def test_put_introduces_remote_signer_for_authenticated_tel_query(tmp_path):
    """Public history does not grant a role; private enrollment survives reopen and revoke."""
    observations = ObservationBaser(name="reader-enrollment", temp=False, headDirPath=str(tmp_path))
    with _remoteSignerLab("observer-remote-signer", authorize=False, observations=observations) as (
        issuer, signer, observerHby, ctx, client, regk, tel,
    ):
        assert issuer.pre != signer.pre
        assert signer.pre not in observerHby.kevers
        # Public introduction establishes identity, but only private enrollment grants access.
        assert _signedTelQuery(client, signer, regk).status == falcon.HTTP_403
        replay = _signerKel(signer)
        assert _putKel(client, replay).status == falcon.HTTP_204
        assert signer.pre in observerHby.kevers
        assert _signedTelQuery(client, signer, regk).status == falcon.HTTP_403
        admin = testing.TestClient(ctx.internalApp)
        path = f"/accounts/{signer.pre}"
        assert admin.simulate_get(path).status_code == 404
        assert admin.simulate_put("/accounts/not-an-aid", json={'roles': ['reader'], 'kel': replay.decode()}).status_code == 400
        assert admin.simulate_get(f"/accounts/{signer.pre}extra").status_code == 400
        assert admin.simulate_delete("/accounts/not-an-aid").status_code == 400
        assert admin.simulate_put(path, json={'roles': ['reader'], 'kel': tel.decode()}).status_code == 400
        assert signer.pre not in ctx.readers
        assert ctx.observations.accounts.get((signer.pre,)) is None
        signer.rotate()
        # The issuer's accepted KEL supports the TEL and legitimately accompanies the reader KEL.
        replay = _signerKel(issuer) + _signerKel(signer)
        assert observerHby.kevers[signer.pre].sn == 0
        response = admin.simulate_put(path, json={'roles': ['reader'], 'kel': replay.decode()})
        assert response.status_code == 200
        assert observerHby.kevers[signer.pre].sn == 1
        assert response.json == dict(aid=signer.pre, roles=['reader'], service=ctx.hab.pre)
        assert admin.simulate_get(path).json == response.json
        assert _telBodies(_signedTelQuery(client, signer, regk).content) == _telBodies(tel)
        with openHby(name="observer-remote-attacker", base="test", temp=True, version=Vrsn_2_0) as attackerHby:
            attacker = attackerHby.makeHab(name="attacker")
            assert _signedTelQuery(client, signer, regk, endorser=attacker).status == falcon.HTTP_401
        assert client.simulate_post("/", body=_telQuery(signer, regk).raw,
            headers={"Content-Type": CESR_CONTENT_TYPE}).status == falcon.HTTP_400

        # Reopen the permission store, then revoke dynamic access without cutting a fixed reader.
        ctx.close()
        observations.reopen()
        reopened = Context(observerHby, hab=observerHby.habByName("observer"), observations=observations,
                           readers=[issuer.pre])
        try:
            assert not reopened.ingest(tel)['rejected']
            client = testing.TestClient(reopened.app)
            admin = testing.TestClient(reopened.internalApp)
            assert admin.simulate_get(path).json['roles'] == ['reader']
            assert _signedTelQuery(client, signer, regk).status_code == 200
            assert admin.simulate_delete(path).status_code == 204
            assert admin.simulate_delete(path).status_code == 204
            assert _signedTelQuery(client, signer, regk).status_code == 403
            assert admin.simulate_get(path).status_code == 404
            static = f"/accounts/{issuer.pre}"
            assert admin.simulate_put(static, json={'roles': ['reader'], 'kel': _signerKel(issuer).decode()}).status_code == 200
            assert admin.simulate_delete(static).status_code == 204
            assert issuer.pre in reopened.readers
            assert _signedTelQuery(client, issuer, regk).status_code == 200
        finally:
            reopened.close()


def test_put_replay_is_idempotent_and_accepts_older_history_after_rotation():
    with _remoteSignerLab("observer-replay") as (
        issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        inception = _signerKel(signer)
        assert _putKel(client, inception).status == falcon.HTTP_204
        signer.rotate()
        current = _signerKel(signer)
        assert _putKel(client, current).status == falcon.HTTP_204
        assert observerHby.kevers[signer.pre].sn == 1
        assert _putKel(client, current).status == falcon.HTTP_204
        assert _putKel(client, inception).status == falcon.HTTP_204
        assert observerHby.kevers[signer.pre].sn == 1


def test_put_accepts_v2_recovery_replay_and_repeat():
    with _remoteSignerLab("observer-v2-recovery") as (
        _issuer,
        _signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        with openHby(
            name="observer-v2-recovery-source",
            base="test",
            temp=True,
            version=Vrsn_2_0,
        ) as sourceHby:
            signers = Salter(raw=b"recovery-test-salt").signers(count=3)
            pre = eventing.incept(
                keys=[signers[0].verfer.qb64],
                ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64],
                version=Vrsn_2_0,
            )
            ixn1 = eventing.interact(pre=pre.pre, dig=pre.said, sn=1, version=Vrsn_2_0)
            ixn2 = eventing.interact(pre=pre.pre, dig=ixn1.said, sn=2, version=Vrsn_2_0)
            recovery = eventing.rotate(
                pre=pre.pre,
                keys=[signers[1].verfer.qb64],
                dig=pre.said,
                sn=1,
                ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64],
                version=Vrsn_2_0,
            )
            messages = [
                bytes(
                    eventing.messagize(
                        serder,
                        sigers=[signer.sign(serder.raw, index=0)],
                        framed=False,
                        gvrsn=Vrsn_2_0,
                    )
                )
                for serder, signer in (
                    (pre, signers[0]),
                    (ixn1, signers[0]),
                    (ixn2, signers[0]),
                    (recovery, signers[1]),
                )
            ]
            Parser(version=Vrsn_2_0).parse(
                ims=bytearray(b"".join(messages)), kvy=sourceHby.kvy
            )
            replay = b"".join(sourceHby.db.clonePreIter(pre=pre.pre, gvrsn=Vrsn_2_0))
            assert sourceHby.kevers[pre.pre].sn == 1
            assert _putKel(client, replay).status == falcon.HTTP_204
            assert _putKel(client, replay).status == falcon.HTTP_204
            assert observerHby.kevers[pre.pre].sn == 1
            assert observerHby.kevers[pre.pre].serder.said == recovery.said
            for serder in (pre, ixn1, ixn2, recovery):
                assert serder.said in observerHby.db.kels.get(
                    keys=serder.pre, on=serder.sn
                )
            assert _putKel(client, b"".join(messages[:3])).status == falcon.HTTP_204
            assert observerHby.kevers[pre.pre].serder.said == recovery.said


def test_put_uses_genus_framing_without_requiring_v2_event_bodies():
    with _remoteSignerLab("observer-put-v1-body") as (
        _issuer,
        _signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        with openHby(
            name="observer-put-v1-signer", base="test", temp=True, version=Vrsn_2_0
        ) as legacyHby:
            legacy = legacyHby.makeHab(name="legacy", version=Vrsn_1_0)
            replay = _signerKel(legacy)
            assert legacy.kever.serder.pvrsn == Vrsn_1_0
            assert _putKel(client, replay).status == falcon.HTTP_204
            assert observerHby.kevers[legacy.pre].serder.pvrsn == Vrsn_1_0


@pytest.mark.parametrize(
    "material",
    [
        "empty",
        "malformed",
        "truncated",
        "missing-signature",
        "bad-signature",
        "non-kel",
    ],
)
def test_put_rejects_invalid_or_non_kel_input(material):
    with _remoteSignerLab(f"observer-put-{material}") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        regk,
        _tel,
    ):
        replay = _signerKel(signer)
        if material == "empty":
            replay = b""
        elif material == "malformed":
            replay = b"not CESR"
        elif material == "truncated":
            replay = replay[:-1]
        elif material == "missing-signature":
            replay = signer.kever.serder.raw
        elif material == "bad-signature":
            with openHby(
                name=f"observer-put-attacker-{material}",
                base="test",
                temp=True,
                version=Vrsn_2_0,
            ) as attackerHby:
                attacker = attackerHby.makeHab(name="attacker")
                replay = bytes(
                    attacker.endorse(
                        signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0
                    )
                )
        elif material == "non-kel":
            qry = _telQuery(signer, regk)
            replay = bytes(signer.endorse(qry, last=True, framed=False, gvrsn=Vrsn_2_0))
        assert _putKel(client, replay).status == falcon.HTTP_400
        assert signer.pre not in observerHby.kevers


@pytest.mark.parametrize("tail", [b"not CESR", b"-"])
def test_put_rejects_malformed_tail_before_processing_valid_prefix(tail):
    with _remoteSignerLab(f"observer-put-tail-{tail!r}") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        serder = SerderKERI(raw=bytearray(replay))
        enclosedReplay = serder.raw + Counter.enclose(
            qb64=replay[serder.size :], code=Codens.AttachmentGroup
        )
        response = _putKel(client, enclosedReplay + tail)
        assert response.status == falcon.HTTP_400
        assert signer.pre not in observerHby.kevers
        assert _putKel(client, replay).status == falcon.HTTP_204


def test_put_rejects_unaccepted_rotation_but_allows_complete_retry():
    with _remoteSignerLab("observer-put-retry") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        inception = _signerKel(signer)
        signer.rotate()
        with openHby(
            name="observer-put-rotation-attacker",
            base="test",
            temp=True,
            version=Vrsn_2_0,
        ) as attackerHby:
            attacker = attackerHby.makeHab(name="attacker")
            invalidRotation = bytes(
                attacker.endorse(
                    signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0
                )
            )
        assert _putKel(client, inception + invalidRotation).status == falcon.HTTP_400
        assert observerHby.kevers[signer.pre].sn == 0
        assert not observerHby.db.kels.get(keys=signer.pre, on=1)
        assert _putKel(client, _signerKel(signer)).status == falcon.HTTP_204
        assert observerHby.kevers[signer.pre].sn == 1


def test_put_checks_every_event_not_only_the_final_rotation():
    with _remoteSignerLab("observer-put-intermediate") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        inception = _signerKel(signer)
        signer.rotate()
        with openHby(
            name="observer-put-intermediate-attacker",
            base="test",
            temp=True,
            version=Vrsn_2_0,
        ) as attackerHby:
            attacker = attackerHby.makeHab(name="attacker")
            invalidRotation = bytes(
                attacker.endorse(
                    signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0
                )
            )
        signer.rotate()
        finalRotation = bytes(
            signer.endorse(signer.kever.serder, last=True, framed=False, gvrsn=Vrsn_2_0)
        )
        assert _putKel(client, inception + invalidRotation + finalRotation).status == (
            falcon.HTTP_400
        )
        assert not observerHby.db.kels.get(keys=signer.pre, on=1)
        assert not observerHby.db.kels.get(keys=signer.pre, on=2)


def test_put_rejects_modified_body_with_previously_accepted_said():
    with _remoteSignerLab("observer-put-said") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        assert _putKel(client, replay).status == falcon.HTTP_204
        changed = replay.replace(signer.pre.encode(), ("E" + "A" * 43).encode(), 1)
        assert changed != replay
        assert _putKel(client, changed).status == falcon.HTTP_400
        assert observerHby.kevers[signer.pre].serder.said == signer.kever.serder.said


def test_put_does_not_hide_one_shot_storage_errors(monkeypatch):
    with _remoteSignerLab("observer-put-storage-error") as (
        issuer,
        signer,
        _observerHby,
        ctx,
        client,
        _regk,
        _tel,
    ):
        originalGet = ctx.kvy.db.kels.get
        calls = 0

        def fail_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("storage unavailable")
            return originalGet(*args, **kwargs)

        monkeypatch.setattr(ctx.kvy.db.kels, "get", fail_once)
        assert _putKel(client, _signerKel(signer)).status == falcon.HTTP_500
        assert calls == 1
        assert originalGet(keys=issuer.pre, on=0)


def test_put_rejects_oversized_attachment_group_before_processing():
    with _remoteSignerLab("observer-put-attachment-group") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        serder = SerderKERI(raw=bytearray(replay))
        attachments = replay[serder.size :]
        group = Counter.enclose(qb64=attachments, code=Codens.AttachmentGroup)
        counter = Counter(qb64b=group[:4])
        malformedGroup = (
            Counter(
                code=Codens.AttachmentGroup,
                count=counter.count + 1,
            ).qb64b
            + attachments
        )
        assert _putKel(client, serder.raw + malformedGroup).status == falcon.HTTP_400
        assert signer.pre not in observerHby.kevers


def test_put_size_limit_content_type_and_allow_header(monkeypatch):
    with _remoteSignerLab("observer-put-limits") as (
        _issuer,
        signer,
        observerHby,
        _ctx,
        client,
        _regk,
        _tel,
    ):
        replay = _signerKel(signer)
        assert _putKel(client, replay, "application/json").status == falcon.HTTP_406
        atLimit = (b"not CESR" + b" " * (8 * 1024 * 1024))[: 8 * 1024 * 1024]
        assert len(atLimit) == 8 * 1024 * 1024
        assert _putKel(client, atLimit).status == falcon.HTTP_400
        assert _putKel(client, replay + b"x" * (8 * 1024 * 1024 + 1)).status == (
            falcon.HTTP_413
        )
        declaredLarge = client.simulate_request(
            method="PUT",
            path="/",
            body=replay,
            headers={"Content-Type": CESR_CONTENT_TYPE},
            extras={"CONTENT_LENGTH": str(8 * 1024 * 1024 + 1)},
        )
        assert declaredLarge.status == falcon.HTTP_413
        assert signer.pre not in observerHby.kevers
        method = client.simulate_get("/")
        assert method.status == falcon.HTTP_405
        assert "PUT" in method.headers["allow"]

    from types import SimpleNamespace

    from kfobserver.app import httping

    class BoundedRead:
        sizes = []

        def read(self, size):
            self.sizes.append(size)
            return b"x" * size

    stream = BoundedRead()
    req = SimpleNamespace(
        content_type=CESR_CONTENT_TYPE,
        content_length=None,
        bounded_stream=stream,
    )
    rep = SimpleNamespace()
    monkeypatch.setattr(httping, "PUT_BODY_LIMIT", 8)
    with pytest.raises(falcon.HTTPError) as error:
        httping.introduceKel(req, rep, None)
    assert error.value.status == falcon.HTTP_413
    assert stream.sizes == [9]


def test_wallet_query_last_all_since_sn():
    """Signed tels / tels/head queries return verified CESR only."""
    with openHby(name="kf-obs-http", base="test", temp=True, version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer")
        observerHab = hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        ripper, bup, _blinder, _acdc, stream = _seedObserverTel(hby, issuer)

        ctx = Context(hby, readers=[wallet.pre])
        try:
            summary = ctx.ingest(stream)
            assert ripper.said in summary["accepted"]

            client = testing.TestClient(ctx.app)

            allQry = _telQuery(wallet, ripper.said, route="tels")
            allResp = _postCesr(client, wallet, allQry)
            assert allResp.status == falcon.HTTP_200
            assert allResp.headers["content-type"] == CESR_CONTENT_TYPE
            assert _telBodies(allResp.content) == _telBodies(stream)
            assert _telIlks(allResp.content) == ["rip", "bup"]

            sinceQry = _telQuery(wallet, ripper.said, route="tels", sn=1)
            sinceResp = _postCesr(client, wallet, sinceQry)
            assert sinceResp.status == falcon.HTTP_200
            assert _telBodies(sinceResp.content) == bytes(bup.raw)

            headQry = _telQuery(wallet, ripper.said, route="tels/head")
            headResp = _postCesr(client, wallet, headQry)
            assert headResp.status == falcon.HTTP_200
            assert _telBodies(headResp.content) == bytes(bup.raw)

            missing = _telQuery(wallet, "E" + "B" * 43, route="tels")
            missingResp = _postCesr(client, wallet, missing)
            assert missingResp.status == falcon.HTTP_404

            bulk = _telQuery(wallet, ripper.said, route="tels/bulk")
            bulkResp = _postCesr(client, wallet, bulk)
            assert bulkResp.status == falcon.HTTP_403

            assert hby.habByName("observer").pre == observerHab.pre
        finally:
            ctx.close()


def test_health():
    """Liveness probe leaks no TEL."""
    with openHby(name="kf-obs-health", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="observer")
        ctx = Context(hby)
        try:
            client = testing.TestClient(ctx.app)
            response = client.simulate_get("/health")
            assert response.status == falcon.HTTP_200
            assert response.json["status"] == "ok"
        finally:
            ctx.close()
