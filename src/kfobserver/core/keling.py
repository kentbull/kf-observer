# -*- encoding: utf-8 -*-
"""
kfobserver.core.keling module

Witness KEL fallback for pending observer TEL batches.
"""

from urllib.parse import urlsplit, urlencode

from hio.base import doing, tyming
from hio.core import http
from keri import help
from keri.app.httping import CESR_CONTENT_TYPE, CESR_DESTINATION_HEADER

from kfobserver.core.observing import ingestKel


logger = help.ogler.getLogger()


def fetchKelDo(owner, issuer, url, aid=None, timeout=5.0):
    """Cooperatively GET witness KEL; return CESR bytes or empty bytes."""
    if not issuer or not url:
        return b""
    purl = urlsplit(url)
    base = (purl.path or "/").rstrip("/")
    path = f"{base}/log?{urlencode({'pre': issuer})}"
    headers = {"Accept": CESR_CONTENT_TYPE}
    if aid:
        headers[CESR_DESTINATION_HEADER] = aid
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
        client.request(method="GET", path=path, headers=headers)
        tymer = tyming.Tymer(tymth=owner.tymth, duration=timeout)
        while not tymer.expired:
            client.service()
            if client.responses:
                response = client.respond()
                if response.status == 200:
                    return bytes(response.body or b"")
                logger.info(
                    "witness KEL fetch %s %s returned HTTP %s",
                    issuer,
                    url,
                    response.status,
                )
                return b""
            if client.respondent is not None and client.respondent.errored:
                break
            yield b""
        logger.info("witness KEL fetch failed for %s at %s", issuer, url)
        return b""
    except OSError as ex:  # Includes socket errors and ssl.SSLError.
        logger.info("witness KEL fetch error for %s at %s: %s", issuer, url, ex)
        return b""
    finally:
        if client is not None:
            client.close()


class WitnessKelFetcher(doing.DoDoer):
    """Poll witnesses for KELs of issuers with pending observer TEL batches."""

    def __init__(self, observer, kvy, witnesses=None, tock=5.0):
        """
        Parameters:
            observer (Observer): pending-batch source and ingest target.
            kvy (Kevery): Kevery bound to the observer Habery Baser.
            witnesses (list[dict] | None): entries with ``url`` and optional ``aid``.
            tock (float): poll interval in seconds.
        """
        self.observer = observer
        self.kvy = kvy
        self.witnesses = list(witnesses or [])
        self.interval = float(tock)
        self.timeout = 5.0
        super(WitnessKelFetcher, self).__init__(doers=[doing.doify(self.fetchDo)])

    def fetchDo(self, tymth=None, tock=0.0, **kwa):
        """Periodic KEL fetch for pending issuers."""
        self.wind(tymth)
        self.tock = tock
        yield self.tock
        while True:
            for issuer in self.observer.pendingIssuers():
                for wit in self.witnesses:
                    raw = yield from fetchKelDo(
                        self,
                        issuer,
                        wit.get("url"),
                        aid=wit.get("aid"),
                        timeout=self.timeout,
                    )
                    if raw:
                        ingestKel(self.kvy, raw)
                        moved = self.observer.retryPending()
                        logger.info(
                            "witness KEL for %s from %s: %s",
                            issuer,
                            wit.get("url"),
                            moved,
                        )
                    if issuer not in self.observer.pendingIssuers():
                        break
            delay = tyming.Tymer(tymth=self.tymth, duration=self.interval)
            yield self.tock
            while not delay.expired:
                yield self.tock
