"""Run the installed service entry point on actual loopback HTTP sockets."""
import json
import os
from uuid import uuid4
import socket
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen

import pytest

from keri.app import Habery
from keri.kering import Vrsn_2_0


PASSCODE = "0123456789abcdefghijk"


SERVER_TLS = Path(__file__).parents[1] / 'tls' / 'server.pem'


def port():
    """Reserve an available loopback port briefly for a local subprocess test."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("scenario", ["fresh", "encrypted-existing",
                                     "clear-existing", "clear-existing-passcode",
                                     "encrypted-missing", "encrypted-wrong"])
def test_installed_cli_runs_its_own_http_service(tmp_path, scenario):
    """Reopen each Keeper mode through the installed service and probe the cache API.

    Parameters:
        tmp_path: private logs; the unique base owns this test's store namespace.
        scenario: new, encrypted, or clear Keeper with valid/absent/irrelevant passcode.
    """
    external, internal = port(), port()
    while internal == external:
        internal = port()
    name, base = "cli-parity", "cli-" + uuid4().hex
    encrypted = scenario == "fresh" or scenario.startswith("encrypted")
    before = None
    if scenario != "fresh":
        hby = Habery(name=name, base=base, bran=PASSCODE if encrypted else None,
                     version=Vrsn_2_0)
        try:
            hab = hby.makeHab(name="observer")
            before = (hab.pre, hby.ks.gbls.get("aeid"), hby.ks.gbls.get("salt"))
        finally:
            hby.close()
    env = dict(os.environ)
    env.pop("KLI_KEYSTORE_PASSCODE", None)
    if scenario in ("fresh", "encrypted-existing"):
        env["KLI_KEYSTORE_PASSCODE"] = PASSCODE
    elif scenario == "encrypted-wrong":
        env["KLI_KEYSTORE_PASSCODE"] = "abcdefghijk0123456789"
    extra = ["--passcode", PASSCODE] if scenario == "clear-existing-passcode" else []
    log = tmp_path / "observer.log"
    with log.open("wb") as output:
        proc = subprocess.Popen([
            "kf-observer", "start", "--name", name, "--base", base,
            "--alias", "observer", "--http", str(external), "--bootport", str(internal),
            "--registrar", "https://127.0.0.1:1/",
            "--registrar-ca", str(SERVER_TLS),
            "--registrar-certedhost", "127.0.0.1=localhost",
            "--timeout", "0.1", "--no-prompt"] + extra,
            env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            if scenario in ("encrypted-missing", "encrypted-wrong"):
                assert proc.wait(timeout=15) != 0
                if scenario == "encrypted-missing":
                    assert "prompting is disabled" in log.read_text()
            else:
                deadline = time.monotonic() + 15
                for endpoint in (external, internal):
                    while True:
                        if proc.poll() is not None:
                            raise AssertionError(log.read_text())
                        try:
                            with urlopen(f"http://127.0.0.1:{endpoint}/health", timeout=.3) as response:
                                # Only the private listener reports per-source pull outcomes.
                                expected = {"status": "ok"} if endpoint == external else {"status": "ok", "sources": {}}
                                assert json.load(response) == expected
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise AssertionError(log.read_text())
                            time.sleep(.05)
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)
    # Reopening after stop/refusal must preserve the identity and Keeper state.
    hby = Habery(name=name, base=base, bran=PASSCODE if encrypted else None,
                 version=Vrsn_2_0)
    try:
        hab = hby.habByName(name="observer")
        assert hab is not None
        after = (hab.pre, hby.ks.gbls.get("aeid"), hby.ks.gbls.get("salt"))
        assert bool(after[1]) is encrypted
        assert after[2]
        if before is not None:
            assert after == before
    finally:
        hby.close()
