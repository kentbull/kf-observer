# -*- encoding: utf-8 -*-
"""
kfobserver.core.pulling module

Periodic bulk TEL pull from one or more kf-registrar external faces.
"""

from urllib.parse import urlsplit

from hio.base import doing, tyming
from hio.core import http
from keri import Vrsn_2_0, help
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import query
from keri.help import helping


logger = help.ogler.getLogger()


def bulkQuery(hab, regk=None, sn=0, route="tels/bulk"):
    """Build a signed-ready V2 qry for registrar bulk TEL.

    Parameters:
        hab (Hab): observer habitat that will endorse the query.
        regk (str | list | None): registry SAID(s); omit for all registries.
        sn (int): first sequence number to include.
        route (str): registrar bulk route (``tels/bulk`` or ``regs``).

    Returns:
        SerderKERI: unsigned query serder (caller endorses).
    """
    q = {}
    if regk is not None:
        q["i"] = regk
    if sn:
        q["sn"] = sn
    return query(
        pre=hab.pre,
        route=route,
        query=q,
        stamp=helping.nowIso8601(),
        version=Vrsn_2_0,
    )


def pullDo(owner, hab, url, regk=None, sn=0, timeout=5.0):
    """Cooperatively POST a signed bulk query; return CESR bytes or empty bytes."""
    serder = bulkQuery(hab, regk=regk, sn=sn)
    body = bytes(hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0))
    purl = urlsplit(url)
    client = None
    try:
        client = http.clienting.Client(
            scheme=purl.scheme or "http",
            hostname=purl.hostname or "127.0.0.1",
            port=purl.port,
            portOptional=True,
            tymth=owner.tymth,
        )
        client.reopen()
        client.request(
            method="POST",
            path=purl.path or "/",
            headers={"Content-Type": CESR_CONTENT_TYPE},
            body=body,
        )
        tymer = tyming.Tymer(tymth=owner.tymth, duration=timeout)
        while not tymer.expired:
            client.service()
            if client.responses:
                response = client.respond()
                if response.status == 200:
                    return bytes(response.body or b"")
                logger.info("registrar pull %s returned HTTP %s", url, response.status)
                return b""
            if client.respondent is not None and client.respondent.errored:
                break
            yield b""
        logger.info("registrar pull failed for %s", url)
        return b""
    except OSError as ex:  # Includes socket errors and ssl.SSLError.
        logger.info("registrar pull error for %s: %s", url, ex)
        return b""
    finally:
        if client is not None:
            client.close()


class RegistrarPuller(doing.DoDoer):
    """Poll configured registrar URLs and ingest verified TEL into Observer."""

    def __init__(self, hab, observer, urls=None, tock=5.0, regk=None, kvy=None):
        """
        Parameters:
            hab (Hab): observer habitat used to sign bulk queries.
            observer (Observer): ingest target.
            urls (list[str] | None): registrar external base URLs.
            tock (float): poll interval in seconds.
            regk (str | list | None): optional registry filter for every pull.
            kvy (Kevery | None): Kevery for leading KEL bytes in bulk.
        """
        self.hab = hab
        self.observer = observer
        self.urls = list(urls or [])
        self.regk = regk
        self.kvy = kvy
        self.interval = float(tock)
        self.timeout = 5.0
        super(RegistrarPuller, self).__init__(doers=[doing.doify(self.pullDo)])

    def pullDo(self, tymth=None, tock=0.0, **kwa):
        """Periodic full-clone pull from each registrar URL."""
        self.wind(tymth)
        self.tock = tock
        yield self.tock
        while True:
            for url in self.urls:
                raw = yield from pullDo(
                    self, self.hab, url, regk=self.regk, timeout=self.timeout
                )
                if raw:
                    summary = self.observer.ingest(raw, kvy=self.kvy)
                    logger.info("pulled %s bytes from %s: %s", len(raw), url, summary)
            self.observer.retryPending()
            delay = tyming.Tymer(tymth=self.tymth, duration=self.interval)
            yield self.tock
            while not delay.expired:
                yield self.tock
