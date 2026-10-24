# Additive full-evidence observer profile

Run `kf-observer start --full-evidence --registrar URL --reader AID --kel FILE`
with `--poll`, `--timeout` and `--maximum-age` as needed. Repeat sources, readers
and bootstrap files. `KLI_KEYSTORE_PASSCODE` follows the existing KLI convention.
The profile requires complete KEL/TEL streams from the registrar's
`--full-evidence` mode. Witness/delegation evidence is verified from those streams;
legacy `--witness` fallback is not silently selected in this profile.

The original bare-TEL service remains selectable by omitting `--full-evidence`.
It is compatibility functionality, not the independently observed freshness
contract qualified for the additive end-to-end profile. In the full-evidence
profile, queries read only local verified state. They cannot trigger acquisition.
An answer requires a recent completed observation from a currently configured
source naming the exact accepted registry head. This records receiver observation,
not globally proven publication time or an additional KRAM timing condition.

## Provenance and boundaries

Base: keri-foundation/kf-observer `d6368aef9497452f5aa2a0657abe1adf5645c69b`.
Git records Evan Asakawa as author of that base; attribution is source lineage,
not responsibility for this fork's changes. Retained service/CLI and original tests derive from that upstream source.
Shared KERIpy pin: `993b58266992b786d044fd3938e114a19d76f62f`.
No editable sibling resolves in the new lock; multidict 6.9.1 is core-required.

| Changed symbols | Lineage / decision |
|---|---|
| `core.evidence.Context.__init__`, `setup` | Local composition of neutral shared KERIpy evidence, observation, polling and query capabilities; informed by qualified KLI observer composition. This fork owns the service process and flags. |
| `start` parser, `runObserver` | Existing upstream entry point extended locally with explicit full-evidence selection, roles, bootstrap, timing and environment passcode convention. |
| `test_evidence` | Local real-signature boundary test informed by KERIpy native-services tests: no source/old source/stale time/wrong head cannot authorize fresh answers. |
| `test_cli` | Adapted from Kent kf-registrar 5bfe35a installed-process test; runs this fork's binary on a real HTTP socket. |

Shared `Observation`, `ObservationBaser`, `ObservedEvidence`, `RegistrarPuller`
and `QueryEnd` were extracted from the qualified KERIpy implementation without
changing their methods (see that revision's `docs/v2-e2e/community-parity.md`).
Core verification and atomic registry acceptance remain single-owned. No KLI
service subprocess is launched here. No issuer or holder secret is hosted.

Open upstream PR 2's cooperative-pull intent is implemented through the shared
qualified poller. Its query-triggered acquisition/direct accepted-state writes
are not adopted. Witness fallback is deferred for the complete-proof profile:
authenticated witness evidence must be supplied by the source, not inferred from
an endpoint's availability. Original upstream fallback remains in the old profile.

## Runtime dependency and component checks

The package declaration and lock retain KERIpy
`993b58266992b786d044fd3938e114a19d76f62f`; no editable sibling or experiment
checkout is required. Run `python -m pytest -q tests` with the installed package
and declared dependencies. Tests remain with this service, including real
process/socket and authenticated evidence regressions. Cross-repository
qualification and its image construction are owned by the experiment repository.

## Preserved legacy wallet KEL introduction

The optional Locksmith legacy observer tests were skipped when the observer
package was absent from the wallet-only image. Running all three against the
installed component exposed HTTP 405: the wallet sends a signed KEL replay by
PUT before its KRAM-authenticated query, but the inherited endpoint exposed only
POST. The complete-evidence profile has a different bootstrap contract.

`app.httping.TelQueryEnd.on_put` is a local compatibility adapter for that
existing wallet contract. It bounds and preflights native key-event/receipt
frames before reusing the existing `observing.ingestKel` and ordinary Kevery.
It does not write accepted rows or authenticate a query by transport success;
204 acknowledges intake, and POST still requires KRAM verification. Mixed
query/TEL bodies are rejected before processing. The GET Allow list and class
description reflect the added method. The 8 MiB bound matches the wallet's
transport bound and is local operational policy, not a protocol constant.

The new component regression uses separate signer/observer Haberies, checks
unknown-signer refusal, signed KEL introduction, rejected mixed/empty/oversized
or wrong-media input, then independently authenticated query behavior. The
existing Locksmith integration covers 0, 4 and 32 prior signer rotations through
real Qt HTTP transport. This fix leaves the separately selected full-evidence
observer module unchanged; source and execution revisions must be recorded
separately from earlier clean artifacts.

Related upstream idea/source: Jay-Alexander Elliot's PR 2 commit
[`68e35f2`](https://github.com/keri-foundation/kf-observer/commit/68e35f2ed22ed9e0fbdc16078f7511b399c9cc1e),
“introduce remote signer KEL history via PUT,” already proposes this endpoint
contract and an 8 MiB handler limit. Its exact source was inspected during the
repair's lineage review. Our method is a separately implemented compatibility
adapter using the retained `ingestKel` entry point and complete message-kind
preflight; it is not a wholesale import of that PR or attribution of our new
code to its author. The PR remains prior art for the interface and bounded
intake approach. Its other acquisition/fallback changes retain the disposition
explained above. Handler limits bound processing input; they are not a claim
that HIO avoids buffering an HTTP body before Falcon dispatch.

## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/kf-observer/blob/987d4d3bc17e4df24d99c82415a51cceae019687/docs/native-parity.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
