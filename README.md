# kf-observer

`kf-observer` independently verifies native ACDC registry evidence from configured
HTTPS registrars and serves an authenticated local cache. Kevery verifies KEL;
Regery alone accepts RIP/BUP events through ordinary anchor/order checks. The
service owns HTTP policy, polling, source trust and store lifecycle.

A reader query never starts or accelerates source acquisition. Unknown registries
return 404; unresolved dependencies in the requested registry return 503. Accepted
history remains available independently of source-observation timestamps or source
configuration changes. KRAM still authenticates requests and enforces its normal
replay policy. There are no Observer-* freshness acceptance headers or gates.

## HTTP contract

| Request | Behavior |
| --- | --- |
| `GET /health` | Listener health only. |
| Signed V2 `qry` `POST /`, route `tels`, `q.i` registry SAID | Accepted KEL support and framed TEL, optionally from integer `q.sn`. |
| Signed V2 `qry` `POST /`, route `tels/head` | Accepted KEL support and the accepted TEL head. |
| `PUT /` with public signed KEL replay | Introduce one AID for request authentication. Full-stream framing/type/8 MiB size preflight precedes Kevery processing; no TEL intake through this endpoint. |

POST requires an explicitly configured reader AID and actual request-author
signatures or a valid own-KEL source seal, plus KRAM. Registrar bulk routes and
credential-SAID status queries are refused. Responses carry independently
verifiable evidence, not an application credential-standing verdict.

Explicitly public BSQ/BSS openings acquired from configured sources survive
accepted storage, pending dependency recovery and reopen. The app attaches them
to accepted HTTP evidence; core TEL clones remain body-only. Pending proofs are
never served. The public service stores no registry roots.

## Install and run

Python 3.14+ and libsodium are required (`brew install libsodium` on macOS or
`apt-get install libsodium-dev` on Debian). The project and lockfile select a
complete published KERIpy commit and require no sibling source checkout.

```sh
uv sync --all-extras
kf-observer start \
  --alias observer \
  --reader '<authorized-reader-AID>' \
  --registrar https://127.0.0.1:6632/ \
  --registrar-ca /absolute/path/to/registrar-ca.pem \
  --registrar-certedhost 127.0.0.1=registrar.example \
  --kel /absolute/path/to/reader-kel.cesr \
  --poll 5 --timeout 5 \
  --host 127.0.0.1 --http 6633
```

Repeat `--registrar`, `--reader` and bootstrap `--kel` as needed. Every outbound
source requires HTTPS and an explicit CA bundle. DNS URLs use the URL hostname;
an IP URL requires the operator's `IP=HOSTNAME` certificate identity mapping.
Redirects, plaintext sources, wrong CA/hostname and ambiguous mappings are
refused. Outbound trust is separate from listener `--keypath`, `--certpath` and
`--cafilepath`. `--config-dir` names the directory above `keri/cf/`.

One cooperative poller keeps fixed cadence and per-source deadlines; failure at
one source does not stop later sources. Optional persisted completion/head rows
are source acquisition telemetry. They never authorize acceptance or make a
cache query imply publication recency.

The former bare-TEL/on-demand/witness profile and its selectors are removed.
The ordinary KERI v1 event-body lane in the core parser is preserved. See the
[test migration and donor accounting](docs/native-observer-migration.md).

## Checks

```sh
pytest tests/kfobserver
ruff check src tests
uv lock --check
```

LMDB checks on this workspace run with Docker-owned state. Source and installed
candidate checks are scoped service evidence; full installed network workflows
and end-to-end qualification are separate.
