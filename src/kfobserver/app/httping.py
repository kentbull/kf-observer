"""HTTP request authentication and public KEL introduction for the v2 observer."""
from dataclasses import asdict
import falcon
from keri import Vrsn_2_0
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Parser, SerderKERI
from keri.kering import ConfigurationError, ExtractionError, MaterialError, ValidationError

PUT_BODY_LIMIT = 8 * 1024 * 1024
KEL_ILKS = ("icp", "rot", "ixn", "dip", "drt")

def _authenticateQuery(dom, ctx, allowed, routes):
    """Enforce observer role policy, then core KRAM query authentication."""
    serder = dom.serder
    if serder.route not in routes or serder.pre not in allowed:
        raise falcon.HTTPForbidden(description="requester or route is not authorized")
    kramer = ctx.kvy.kramer
    if kramer is None:
        raise falcon.HTTPServiceUnavailable(description="KRAM unavailable")
    kwa = {key: list(getattr(dom, key))
           for key in ("sigers", "cigars", "lsgs", "tsgs", "sscs", "ssts")}
    try:
        kramer.authenticateQuery(serder, kwa, hby=ctx.hby)
    except ConfigurationError as ex:
        raise falcon.HTTPServiceUnavailable(description=str(ex)) from ex
    except Exception as ex:
        raise falcon.HTTPUnauthorized(description=str(ex)) from ex
    return serder, serder.sad["q"]


def introduceKel(req, rep, ctx):
    """Preflight the whole bounded replay before ordinary Kevery processing."""
    ctype = (req.content_type or "").split(";")[0].strip().lower()
    if ctype and ctype != CESR_CONTENT_TYPE:
        raise falcon.HTTPNotAcceptable(description="Unacceptable content type.")
    if req.content_length is not None and req.content_length > PUT_BODY_LIMIT:
        raise falcon.HTTPContentTooLarge(description="KEL replay exceeds the 8 MiB limit.")
    raw = req.bounded_stream.read(PUT_BODY_LIMIT + 1)
    if len(raw) > PUT_BODY_LIMIT:
        raise falcon.HTTPContentTooLarge(description="KEL replay exceeds the 8 MiB limit.")
    parser = Parser(version=Vrsn_2_0, local=False)
    try:
        generator = parser.groupParsator(ims=bytearray(raw), framed=True,
                                         processive=False, local=False)
        while True:
            try:
                next(generator)
            except StopIteration as done:
                events = done.value
                break
        if not events or any(not isinstance(dom.serder, SerderKERI)
                             or dom.serder.ilk not in KEL_ILKS for dom in events):
            raise ValidationError("replay must contain only complete KEL events")
        if len({dom.serder.pre for dom in events}) != 1:
            raise ValidationError("replay must contain one AID")
    except (ExtractionError, MaterialError, ValidationError) as ex:
        raise falcon.HTTPBadRequest(description="invalid or incomplete KEL replay") from ex
    # Storage errors propagate to Falcon as server errors; they are not bad input.
    for dom in events:
        event = dom.serder
        if event.said in ctx.kvy.db.kels.get(keys=event.pre, on=event.sn):
            continue
        try:
            parser.msgProcess(asdict(dom), kvy=ctx.kvy, tvy=None,
                              exc=None, rvy=None, vry=None)
        except (ExtractionError, MaterialError, ValidationError) as ex:
            raise falcon.HTTPBadRequest(description="KEL replay was not accepted") from ex
    if any(dom.serder.said not in ctx.kvy.db.kels.get(
            keys=dom.serder.pre, on=dom.serder.sn) for dom in events):
        raise falcon.HTTPBadRequest(description="KEL replay was not fully accepted")
    ctx.kvy.processEscrows()
    ctx.rgy.processEscrows()
    ctx._reconcileOpenings()
    rep.status = falcon.HTTP_204


def preflightEnrollmentKel(raw):
    """Check complete KEL-only framing without restricting legitimate dependency AIDs."""
    if not raw or len(raw) > PUT_BODY_LIMIT:
        raise falcon.HTTPBadRequest(description="invalid KEL replay size")
    parser = Parser(version=Vrsn_2_0, local=False)
    try:
        generator = parser.groupParsator(ims=bytearray(raw), framed=True,
                                         processive=False, local=False)
        while True:
            try:
                next(generator)
            except StopIteration as done:
                events = done.value
                break
        if not events or any(not isinstance(dom.serder, SerderKERI)
                             or dom.serder.ilk not in KEL_ILKS + ("rct",) for dom in events):
            raise ValidationError("enrollment evidence must contain only complete KEL events")
    except (ExtractionError, MaterialError, ValidationError) as ex:
        raise falcon.HTTPBadRequest(description="invalid or incomplete KEL replay") from ex
