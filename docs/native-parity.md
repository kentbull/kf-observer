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
Shared KERIpy pin: `ae144adbadc10aa40a057d600fd4546f08275e1d`.
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

## Checks

Sixteen installed-package tests pass in Linux, including all fourteen original
tests, exact-source/head freshness rejection, and a real service subprocess.
Docker copies source and uses named volumes for LMDB. Combined Bash profiles,
hosted witnesses and Locksmith acceptance are later gates, not established by
this component result.

## Common runtime pin and source-review boundary

The additive qualification now uses KERIpy
`993b58266992b786d044fd3938e114a19d76f62f` and this component at
`683679889ad4b22114ebbae0a79e4b2bdb3777bb`. Earlier pins and results above are
historical checkpoints. The package declaration and lock select the same exact
core revision; no sibling editable source is required. The pin follow-up changes
no application symbol or protocol policy.

A fresh clone installed in the common Linux scenario image passes all 16
component tests. The clean multi-component story matrix is recorded separately;
a component suite alone does not establish that outcome. Existing changed-symbol
lineage remains the application source audit, with Git history retaining the
individual predecessor lines and contributors.

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
