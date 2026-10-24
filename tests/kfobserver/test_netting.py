"""Resource-limit wiring at the observer service boundary."""

from types import SimpleNamespace

import falcon
import pytest

from kfobserver.core import netting


def test_http_server_and_client_have_explicit_hio_budgets():
    server = netting.boundedHttpServer("127.0.0.1", 0, falcon.App())
    try:
        assert server.requestHeaderLimit == 64 * 1024
        assert server.requestBodyLimit == 8 * 1024 * 1024
        assert server.requestTimeout == 20.0
        assert server.servant.maxConnections == 128
        assert server.servant.acceptsPerTurn == 16
        assert server.servant.rxbsLimit == 9 * 1024 * 1024
        assert server.servant.rxbsPerTurn == 64 * 1024
        assert netting.clientLimits() == dict(
            responseBodyLimit=8 * 1024 * 1024,
            rxbsLimit=9 * 1024 * 1024,
        )
    finally:
        server.close()


def test_clone_rejects_aggregate_history_before_building_response():
    regks = [f"registry-{index}" for index in range(5)]
    heads = SimpleNamespace(
        getTopItemIter=lambda: iter((((regk,), object()) for regk in regks)))
    ctx = SimpleNamespace(
        reger=SimpleNamespace(heads=heads),
        store=SimpleNamespace(headEvent=lambda _regk: SimpleNamespace(sn=1023)),
    )
    with pytest.raises(falcon.HTTPContentTooLarge) as error:
        netting.boundedClone(ctx)
    assert "aggregate event limit" in error.value.description


def test_legacy_clone_stops_reading_once_response_budget_is_exceeded():
    def rows():
        yield b'x' * (netting.MAX_RESPONSE_BODY + 1)
        raise AssertionError('over-budget history was still read')

    observer = SimpleNamespace(
        store=SimpleNamespace(headEvent=lambda _regk: SimpleNamespace(sn=1)),
        cloneTelIter=lambda _regk, sn: rows(),
        clone=lambda _regk, sn: (_ for _ in ()).throw(
            AssertionError('over-budget response was built')),
    )
    with pytest.raises(falcon.HTTPContentTooLarge):
        netting.boundedLegacyClone(observer, 'registry')
