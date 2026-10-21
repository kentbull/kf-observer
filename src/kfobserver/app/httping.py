# -*- encoding: utf-8 -*-
"""
kfobserver.app.httping module

Falcon resources for the wallet/verifier verified-TEL query face.
"""

import json

import falcon
from keri import Vrsn_2_0
from keri.app.httping import CESR_ATTACHMENT_HEADER, CESR_CONTENT_TYPE
from keri.core import Number, Parser, SerderKERI
from keri.kering import MissingAuthAttachmentError, MissingSenderKeyStateError

from kfobserver.core.observing import ingestKel


# Fine-grained wallet/verifier routes (one registry SAID).
QUERY_ROUTES = ("tels", "tels/head")
# Registrar bulk routes are not served here.
BULK_ROUTES = ("tels/bulk", "regs")


def _snFromQuery(qry):
    """Parse an optional sequence number from a query block."""
    sn = qry.get("sn", 0)
    if sn is None or sn == "":
        return 0
    if isinstance(sn, int):
        return sn
    return Number(num=sn).sn


def _registrySaid(qry):
    """Require a single registry SAID in q.i."""
    raw = qry.get("i")
    if raw is None or raw == "":
        return None
    if isinstance(raw, (list, tuple)):
        if len(raw) != 1:
            return None
        return raw[0]
    return raw


def _loadQueryStream(req):
    """Read a signed qry as CESR-over-HTTP JSON+attachment or a raw CESR stream."""
    ctype = (req.content_type or "").split(";")[0].strip().lower()
    if ctype and ctype != CESR_CONTENT_TYPE:
        raise falcon.HTTPError(
            falcon.HTTP_NOT_ACCEPTABLE,
            title="Content type error",
            description="Unacceptable content type.",
        )
    raw = req.bounded_stream.read()
    if not raw:
        raise falcon.HTTPBadRequest(description="empty body")
    atc = req.get_header(CESR_ATTACHMENT_HEADER, default=None)
    if atc and raw.lstrip()[:1] == b"{":
        payload = json.loads(raw)
        serder = SerderKERI(sad=payload)
        ims = bytearray(serder.raw)
        ims.extend(atc.encode("utf-8") if isinstance(atc, str) else atc)
        return ims
    ims = bytearray(raw)
    if atc and raw.lstrip()[:1] != b"{":
        ims.extend(atc.encode("utf-8") if isinstance(atc, str) else atc)
    return ims


class HealthEnd:
    """Liveness probe. No TEL material."""

    def on_get(self, _req, rep):
        rep.media = dict(status="ok")
        rep.status = falcon.HTTP_200


class TelQueryEnd:
    """Legacy bare-TEL query face with separate signed KEL introduction.

    PUT supplies public key-history evidence; POST still authenticates each
    query through KRAM. This is not the full-evidence observation profile.
    """

    def __init__(self, ctx):
        self.ctx = ctx

    def on_get(self, _req, _rep):
        """Reject unsigned reads and advertise the separate query/introduction methods."""
        raise falcon.HTTPMethodNotAllowed(
            ["POST", "PUT"], description="use signed CESR qry POST or KEL PUT"
        )

    def on_put(self, req, rep):
        """Process a bounded native KEL replay before a wallet's signed query.

        ``req`` carries CESR key events/receipts only; ``rep`` receives 204
        after ordinary Kevery processing. That status acknowledges intake,
        not authentication of a later query or acceptance of every dependency.
        Preflight the complete message kinds before any processor mutation;
        unsupported media, malformed framing or non-KEL messages return 4xx.
        Missing evidence remains subject to the existing Kevery escrows.
        """
        if (req.content_type or '').split(';')[0].strip().lower() != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        limit = 8 * 1024 * 1024  # Match the wallet's bounded service transport.
        raw = req.bounded_stream.read(limit + 1)
        if not raw:
            raise falcon.HTTPBadRequest(description='empty KEL body')
        if len(raw) > limit:
            raise falcon.HTTPContentTooLarge(description='KEL body exceeds size limit')
        ims = bytearray(raw)
        parser = Parser(version=Vrsn_2_0)
        try:
            while ims:
                before = len(ims)
                dom = parser.parseOne(ims=ims, processive=False)
                serder = getattr(dom, 'serder', None)
                if (len(ims) >= before or not isinstance(serder, SerderKERI)
                        or serder.pvrsn != Vrsn_2_0
                        or serder.ilk not in ('icp', 'rot', 'ixn', 'dip', 'drt', 'rct')):
                    raise ValueError('expected complete native key events or receipts')
            # Reuse the existing signed KEL intake; never write accepted rows here.
            ingestKel(self.ctx.kvy, raw)
        except Exception as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex
        rep.status = falcon.HTTP_204

    def on_post(self, req, rep):
        try:
            ims = _loadQueryStream(req)
        except falcon.HTTPError:
            raise
        except Exception as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex

        try:
            dom = Parser(version=Vrsn_2_0).parseOne(
                ims=bytearray(ims), framed=True, processive=False
            )
        except Exception as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex
        if not getattr(dom, "serder", None):
            raise falcon.HTTPBadRequest(description="unable to parse signed query")
        serder = dom.serder
        if serder.ilk != "qry":
            raise falcon.HTTPBadRequest(description="observer face accepts qry messages only")

        route = serder.ked.get("r", "")
        qry = serder.ked.get("q") or {}
        if not isinstance(qry, dict):
            qry = {}

        if route in BULK_ROUTES:
            raise falcon.HTTPForbidden(
                description="bulk registrar routes are not served by the observer"
            )
        if route not in QUERY_ROUTES:
            raise falcon.HTTPForbidden(description=f"invalid observer query route {route}")
        if "vcid" in qry:
            raise falcon.HTTPForbidden(
                description="credential SAID queries are not served; use registry SAID"
            )

        kwa = dict(
            sigers=list(dom.sigers),
            cigars=list(dom.cigars),
            lsgs=list(dom.lsgs),
            tsgs=list(dom.tsgs),
            sscs=list(dom.sscs),
            ssts=list(dom.ssts),
        )

        kramer = self.ctx.kvy.kramer
        if kramer is not None:
            kramer.reconcileConfig()
            try:
                result = kramer.intake(serder, kwa)
            except (MissingAuthAttachmentError, MissingSenderKeyStateError) as ex:
                raise falcon.HTTPUnauthorized(description=str(ex)) from ex
            if result is None:
                raise falcon.HTTPUnauthorized(description="KRAM rejected query")

        regk = _registrySaid(qry)
        if not regk:
            raise falcon.HTTPBadRequest(
                description="q.i must be a single registry SAID"
            )
        if not self.ctx.observer.hasRegistry(regk):
            # IPEX timing: holder may have just published; pull that SAID now.
            if self.ctx.registrars:
                self.ctx.pullRegistry(regk)
        if not self.ctx.observer.hasRegistry(regk):
            if regk in self.ctx.observer.pending:
                raise falcon.HTTPServiceUnavailable(
                    description=(
                        f"registry {regk} pending issuer KEL anchors; retry later"
                    )
                )
            raise falcon.HTTPNotFound(description=f"unknown registry {regk}")

        if route == "tels/head":
            data = self.ctx.observer.lastRaw(regk)
        else:
            sn = _snFromQuery(qry)
            data = self.ctx.observer.clone(regk, sn=sn)

        rep.set_header("Content-Type", CESR_CONTENT_TYPE)
        rep.status = falcon.HTTP_200
        rep.data = data
