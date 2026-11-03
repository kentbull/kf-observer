# Native observer owner and retained guarantees

Base: `dedd89e377937d0d7b628abb896f6a1d2fb401ee`. Later donor:
`bf56f2a654f9ef4e1d861facb004e747a62f2434`. Core reference:
`9576e89ab196136d26576845e5b7f961372b5e08`.

Read the native owner in `evidence_observing.py`, HTTP introduction/authentication
in `app/httping.py`, cache routes in `evidence_querying.py`, then the tests below.
There is one Kevery/Regery/Parser lifecycle. No application writes accepted TEL
ordinals or heads. The former bare-TEL owner, its on-demand/witness acquisition,
and its CLI selector are removed together; these were alternative v2 behaviors,
not the ordinary KERI v1 event-body lane.

| Prior test or source guarantee | Native disposition |
| --- | --- |
| `test_observing`: accepted contiguous history, all/head/since | Native intake and authenticated `test_serving` selection retain exact event order; HTTP now includes supporting KEL and framed TEL. |
| `test_observing`: unanchored input and later KEL | Full-owner reopen in `test_evidence` keeps unresolved ordinals pending, then accepts only after ordinary KEL arrival. |
| `test_observing`: anchored fork, replay monotonicity, later progress | `test_native_ordering_replay_conflict_and_forward_progress` uses independent source/cache Haberies and the real native owner. |
| `test_observing`: tampered body, verifier opening | Native tamper/retry test plus BSQ/BSS public-proof query, independent intake and reopen variants. |
| `test_ipex_presentation_compat`: opaque grant-like SAID and tampered TEL | Native acceptance/tamper and real-ACDC public-proof tests retain service guarantees. The old test did not execute IPEX; no IPEX interoperability claim is retained. |
| `test_keling`: KEL+TEL split, separate Haberies, preloaded KEL | Ordinary Parser demultiplexing and native acceptance tests replace the private splitter; independent public-proof and remote-reader stories retain separate stores. |
| `test_keling`: direct witness search and query-triggered fallback | Removed with that acquisition path. The selected owner acquires complete evidence independently from configured HTTPS sources. |
| `test_keling`: polling, transport failure, cleanup, scheduler progress | Existing real HTTPS evidence tests retain exact-source success, wrong CA/hostname refusal, malformed/failed first source followed by a healthy source, original polling deadlines, and real in-flight TLS cancellation cleanup. Cache queries before/after a poll cannot start or accelerate it. |
| `test_serving`: three-Habery reader introduction and forged/unsigned queries | Carried forward through PUT and signed POST on the sole native QueryEnd. Explicit reader roles and KRAM remain required. |
| `test_serving`: replay, rotation, recovery, KERI v1 bodies under genus framing | Carried forward through ordinary Kevery; no old v2 acceptance engine remains. |
| `test_serving`: malformed/truncated/non-KEL/forged input and malformed tails | Whole-stream framing/type/size preflight remains side-effect-free before Kevery processing; valid complete retries still succeed. |
| `test_serving`: every intermediate event, substituted SAID, one-shot storage failure | Carried forward; invalid events cannot be laundered by a later valid event and storage errors remain server errors. |
| `test_serving`: oversized groups, body limit, content type, bounded read, allowed methods | Carried forward with the existing 8 MiB limit. |
| `test_serving`: cache selection and health | Retained; head/since select accepted TEL events while supporting KEL remains in the response. |
| `test_serving`: on-demand request completion and witness-client mocks | Removed with request-triggered acquisition. Independent source polling has its own TLS, failure and cancellation guarantees. A cache read never starts a pull. |
| Freshness age/header and source-rotation query refusals | Superseded by selected upstream policy and later donor `61fc428`. Accepted history remains queryable independently of observation age/config changes; requests still pass ordinary KRAM. |
| Later donor source-scoped pending/complete-pull records | Retained and extended with real BSQ/BSS pending-proof promotion. An unrelated registry cannot block another source; stale input cannot invent another source's newer head. |
| Later donor rival-at-accepted-slot `maes` assertion | Superseded by native `_RegEventer._validateEvent`: a different SAID at an accepted ordinal is rejected before escrow. Cache success, accepted slot/head, source records and full reopen remain asserted. No synthetic escrow is inserted. |
| Old producer observation schema compatibility helper | Removed. Current observation persistence is exercised by full-store reopen, without a legacy reader or compatibility owner. |

Later donor app HTTP ownership and owned-store shutdown are retained through the
new native composition. HTTPS trust and its source-client failure containment
were already present at the maintained base and remain in use. Repeated donor
core pins are replaced by the selected published SHA. Unrelated msgpack and
setuptools lock updates are not imported; the maintained lock changes only its
core revision.

Public BSQ/BSS material is explicitly retained only from configured-source
acquisition. Exact ordinary dependency escrow may hold its canonical proof until
TEL acceptance; promotion uses accepted-only `putOpening`, and removed/rejected
candidates lose the pending proof. Pending material is never cloned. Source
completion rows are acquisition telemetry, not credential-standing or freshness
verdicts. Installed service/network workflows and complete IPEX qualification
remain separate.
