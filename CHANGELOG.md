# CHANGELOG

<!-- version list -->

## v0.16.4 (2026-07-23)

### Bug Fixes

- Deploy screeners over one SSH session
  ([#57](https://github.com/ditto-assistant/ditto-screener/pull/57),
  [`83f0f64`](https://github.com/ditto-assistant/ditto-screener/commit/83f0f642731b9a3475b96c17ab9bf923fa577fae))


## v0.16.3 (2026-07-23)

### Bug Fixes

- **security**: Pass screening attempt_id on artifact download
  ([#55](https://github.com/ditto-assistant/ditto-screener/pull/55),
  [`806f493`](https://github.com/ditto-assistant/ditto-screener/commit/806f493f86d92b6723d4645ebd43c7ce4c17cb21))


## v0.16.2 (2026-07-23)

### Bug Fixes

- Reinstall embedded signing protocol on deploy
  ([#56](https://github.com/ditto-assistant/ditto-screener/pull/56),
  [`d3188a8`](https://github.com/ditto-assistant/ditto-screener/commit/d3188a87c000c659591abfaa0ac7e312ac717c79))


## v0.16.1 (2026-07-23)

### Bug Fixes

- Keep screener runtime state writable
  ([#49](https://github.com/ditto-assistant/ditto-screener/pull/49),
  [`93297b8`](https://github.com/ditto-assistant/ditto-screener/commit/93297b85f098fb1d9d2ceb0fa135223aefcb787c))


## v0.16.0 (2026-07-23)

### Bug Fixes

- Stop quarantining malformed preflight handling
  ([#48](https://github.com/ditto-assistant/ditto-screener/pull/48),
  [`63624c2`](https://github.com/ditto-assistant/ditto-screener/commit/63624c20f89501273d98413e84627e4270b8de93))

### Features

- Bind reviewer settings into screener verdicts
  ([#47](https://github.com/ditto-assistant/ditto-screener/pull/47),
  [`e7980dc`](https://github.com/ditto-assistant/ditto-screener/commit/e7980dc4a92c2e3152a6a9bdaea0a63307014467))


## v0.15.2 (2026-07-23)

### Bug Fixes

- Require runtime reachability for source holds
  ([#46](https://github.com/ditto-assistant/ditto-screener/pull/46),
  [`e91376b`](https://github.com/ditto-assistant/ditto-screener/commit/e91376bab0df2289206f2e466015931a750dc8b5))


## v0.15.1 (2026-07-23)

### Bug Fixes

- Keep inert Rust targets out of decisive preflight
  ([#45](https://github.com/ditto-assistant/ditto-screener/pull/45),
  [`1304183`](https://github.com/ditto-assistant/ditto-screener/commit/130418342ee6718d59de99dd19b5f0012651dddc))


## v0.15.0 (2026-07-22)

### Bug Fixes

- Align agentic review with benchmark v5 and v6
  ([#41](https://github.com/ditto-assistant/ditto-screener/pull/41),
  [`42ad63f`](https://github.com/ditto-assistant/ditto-screener/commit/42ad63fb129baa45a3a57cf83c646b7855223664))

- Balance anti-copy escalation boundaries
  ([#41](https://github.com/ditto-assistant/ditto-screener/pull/41),
  [`42ad63f`](https://github.com/ditto-assistant/ditto-screener/commit/42ad63fb129baa45a3a57cf83c646b7855223664))

- Harden screener anti-copy boundaries
  ([#41](https://github.com/ditto-assistant/ditto-screener/pull/41),
  [`42ad63f`](https://github.com/ditto-assistant/ditto-screener/commit/42ad63fb129baa45a3a57cf83c646b7855223664))

- Keep dynamic review workers analyzer-ready
  ([#43](https://github.com/ditto-assistant/ditto-screener/pull/43),
  [`d75c6e3`](https://github.com/ditto-assistant/ditto-screener/commit/d75c6e3c3898f625932912a1837f02ef405029e3))

### Features

- Apply platform-managed review settings
  ([#43](https://github.com/ditto-assistant/ditto-screener/pull/43),
  [`d75c6e3`](https://github.com/ditto-assistant/ditto-screener/commit/d75c6e3c3898f625932912a1837f02ef405029e3))

- Manage agentic reviewer settings from platform
  ([#43](https://github.com/ditto-assistant/ditto-screener/pull/43),
  [`d75c6e3`](https://github.com/ditto-assistant/ditto-screener/commit/d75c6e3c3898f625932912a1837f02ef405029e3))

- Persist attempt-bound shadow reviewer telemetry
  ([#43](https://github.com/ditto-assistant/ditto-screener/pull/43),
  [`d75c6e3`](https://github.com/ditto-assistant/ditto-screener/commit/d75c6e3c3898f625932912a1837f02ef405029e3))

- Report applied reviewer revision
  ([#43](https://github.com/ditto-assistant/ditto-screener/pull/43),
  [`d75c6e3`](https://github.com/ditto-assistant/ditto-screener/commit/d75c6e3c3898f625932912a1837f02ef405029e3))

### Testing

- Bind v5 v6 calibration to reviewer revisions
  ([#41](https://github.com/ditto-assistant/ditto-screener/pull/41),
  [`42ad63f`](https://github.com/ditto-assistant/ditto-screener/commit/42ad63fb129baa45a3a57cf83c646b7855223664))

- Cover shipped v5 and v6 starter controls
  ([#41](https://github.com/ditto-assistant/ditto-screener/pull/41),
  [`42ad63f`](https://github.com/ditto-assistant/ditto-screener/commit/42ad63fb129baa45a3a57cf83c646b7855223664))

- Pin live reviewer control to benchmark v6 starter
  ([#41](https://github.com/ditto-assistant/ditto-screener/pull/41),
  [`42ad63f`](https://github.com/ditto-assistant/ditto-screener/commit/42ad63fb129baa45a3a57cf83c646b7855223664))


## v0.14.2 (2026-07-21)

### Bug Fixes

- Mask triple-quoted strings in static preflight
  ([#42](https://github.com/ditto-assistant/ditto-screener/pull/42),
  [`9795ce7`](https://github.com/ditto-assistant/ditto-screener/commit/9795ce7e3b0038622df2212941bcb41483cf9a5f))


## v0.14.1 (2026-07-21)

### Bug Fixes

- Ignore inert prompt text in malicious preflight
  ([#39](https://github.com/ditto-assistant/ditto-screener/pull/39),
  [`d14a57b`](https://github.com/ditto-assistant/ditto-screener/commit/d14a57bef239bbd185348ae387a86e472085d2d2))


## v0.14.0 (2026-07-21)

### Bug Fixes

- **gate**: Skip the image-binding advisory on a build-only screen
  ([#40](https://github.com/ditto-assistant/ditto-screener/pull/40),
  [`76c9a42`](https://github.com/ditto-assistant/ditto-screener/commit/76c9a42ad958fa6e074215ea833f1486347b44d0))

### Features

- Build-only screening pass for approved-but-unbuilt submissions
  ([#40](https://github.com/ditto-assistant/ditto-screener/pull/40),
  [`76c9a42`](https://github.com/ditto-assistant/ditto-screener/commit/76c9a42ad958fa6e074215ea833f1486347b44d0))


## v0.13.2 (2026-07-21)

### Bug Fixes

- Allow best-effort preflight posts
  ([#38](https://github.com/ditto-assistant/ditto-screener/pull/38),
  [`bdd51cf`](https://github.com/ditto-assistant/ditto-screener/commit/bdd51cfd44526fa69ab424291f3b01baeb40dff1))


## v0.13.1 (2026-07-20)

### Bug Fixes

- Allow required DittoBench preflight
  ([#37](https://github.com/ditto-assistant/ditto-screener/pull/37),
  [`7b787a7`](https://github.com/ditto-assistant/ditto-screener/commit/7b787a7bf881fd181c4c9f254e945081e947b05a))


## v0.13.0 (2026-07-20)

### Bug Fixes

- Adjudicate mixed quarantine causes
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Allow request-local tool memoization
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Budget cached partial reviews ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Harden L2 causal evidence and partial dossiers
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Hold review-adaptive model routing
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Require cross-category scorer clearance
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Validate strict SOL tool contracts live
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

### Continuous Integration

- Validate the shipped v3 starter revision
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

### Documentation

- Explain review-adaptation holds ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Record activated v4 rollout ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Refresh v4 shadow rollout state ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

### Features

- Add agentic Kimi and SOL source review
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Add agentic Kimi/GLM L2 and SOL clearance review
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Expose layered review progress safely
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Support versioned v2 and v3 starter baselines
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

### Testing

- Align live reviewer output budget
  ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))

- Retry fail-safe live reviews ([#34](https://github.com/ditto-assistant/ditto-screener/pull/34),
  [`5e1f260`](https://github.com/ditto-assistant/ditto-screener/commit/5e1f2604ebf1e3e0189995b7071720f34f8ed5ff))


## v0.12.1 (2026-07-19)

### Bug Fixes

- Mirror validator runtime during screening
  ([#36](https://github.com/ditto-assistant/ditto-screener/pull/36),
  [`8a4050f`](https://github.com/ditto-assistant/ditto-screener/commit/8a4050fc21c8bbf803ff73f59cfb004c7fe8c19c))


## v0.12.0 (2026-07-18)

### Features

- Publish screened Docker images ([#26](https://github.com/ditto-assistant/ditto-screener/pull/26),
  [`e9fd80a`](https://github.com/ditto-assistant/ditto-screener/commit/e9fd80a043aea1dae0c024fcfaffac057c5593fb))


## v0.11.2 (2026-07-18)

### Bug Fixes

- Detect coordinated generator mirroring
  ([#28](https://github.com/ditto-assistant/ditto-screener/pull/28),
  [`83f0fb3`](https://github.com/ditto-assistant/ditto-screener/commit/83f0fb31af08cb87ac614976e4ec48b7a89967be))

- Tighten screener evidence boundary
  ([#28](https://github.com/ditto-assistant/ditto-screener/pull/28),
  [`83f0fb3`](https://github.com/ditto-assistant/ditto-screener/commit/83f0fb31af08cb87ac614976e4ec48b7a89967be))


## v0.11.1 (2026-07-18)

### Bug Fixes

- Attribute OpenRouter requests to Ditto
  ([#33](https://github.com/ditto-assistant/ditto-screener/pull/33),
  [`6d2ef3b`](https://github.com/ditto-assistant/ditto-screener/commit/6d2ef3b4692fa81cc844e52fd1e388a59f9ef6b2))


## v0.11.0 (2026-07-17)

### Documentation

- **policy-modules**: Tighten oracle wording, drop em-dashes
  ([#31](https://github.com/ditto-assistant/ditto-screener/pull/31),
  [`63d6350`](https://github.com/ditto-assistant/ditto-screener/commit/63d6350f7bd65a635037673048473f153123192d))

### Features

- Indistinguishable oracle envelope and audit-gated-routing lead
  ([#32](https://github.com/ditto-assistant/ditto-screener/pull/32),
  [`c2531d1`](https://github.com/ditto-assistant/ditto-screener/commit/c2531d1d5971771a7991445392576636f5f62e45))


## v0.10.0 (2026-07-17)

### Features

- **screener**: Indistinguishable behavioral oracle + audit-detection review
  ([#29](https://github.com/ditto-assistant/ditto-screener/pull/29),
  [`529e061`](https://github.com/ditto-assistant/ditto-screener/commit/529e061a73730a0a8be874677031a15044ddd8c8))


## v0.9.2 (2026-07-17)

### Bug Fixes

- Strengthen source-review reachable evidence
  ([#27](https://github.com/ditto-assistant/ditto-screener/pull/27),
  [`ea2b1ad`](https://github.com/ditto-assistant/ditto-screener/commit/ea2b1ad5c0e12090fa8e48cf066ab12cebd17dbf))


## v0.9.1 (2026-07-17)

### Bug Fixes

- Deploy semantic release commits ([#25](https://github.com/ditto-assistant/ditto-screener/pull/25),
  [`5b31848`](https://github.com/ditto-assistant/ditto-screener/commit/5b31848e00d732f1d72aa017e010e8afc12b6a86))


## v0.9.0 (2026-07-17)

### Features

- Add bounded binary analysis to source review
  ([#24](https://github.com/ditto-assistant/ditto-screener/pull/24),
  [`d65caed`](https://github.com/ditto-assistant/ditto-screener/commit/d65caed9df17eb119fe10ba3192988d305303713))


## v0.8.0 (2026-07-17)

### Code Style

- Ruff format + line length ([#19](https://github.com/ditto-assistant/ditto-screener/pull/19),
  [`d87d423`](https://github.com/ditto-assistant/ditto-screener/commit/d87d4235052672af99351f51977651472eadc80d))

### Features

- Log per-stage wall-clock timings for every screening
  ([#19](https://github.com/ditto-assistant/ditto-screener/pull/19),
  [`d87d423`](https://github.com/ditto-assistant/ditto-screener/commit/d87d4235052672af99351f51977651472eadc80d))


## v0.7.2 (2026-07-17)

### Bug Fixes

- Clarify benchmark emulation boundary
  ([#11](https://github.com/ditto-assistant/ditto-screener/pull/11),
  [`21ad169`](https://github.com/ditto-assistant/ditto-screener/commit/21ad16979215177d56c0c489da1d2ecf67026247))


## v0.7.1 (2026-07-17)

### Bug Fixes

- Apply IMDS guard updates safely ([#23](https://github.com/ditto-assistant/ditto-screener/pull/23),
  [`50f3fa1`](https://github.com/ditto-assistant/ditto-screener/commit/50f3fa1a4e50687ca66c468a44101144594136da))

- Preserve GCE DNS in screener IMDS guard
  ([#23](https://github.com/ditto-assistant/ditto-screener/pull/23),
  [`50f3fa1`](https://github.com/ditto-assistant/ditto-screener/commit/50f3fa1a4e50687ca66c468a44101144594136da))

### Code Style

- Format IMDS guard regression tests
  ([#23](https://github.com/ditto-assistant/ditto-screener/pull/23),
  [`50f3fa1`](https://github.com/ditto-assistant/ditto-screener/commit/50f3fa1a4e50687ca66c468a44101144594136da))


## v0.7.0 (2026-07-16)

### Features

- **heartbeat**: Sign a per-instance id (protocol v3)
  ([#22](https://github.com/ditto-assistant/ditto-screener/pull/22),
  [`bf1f8ff`](https://github.com/ditto-assistant/ditto-screener/commit/bf1f8ff476af7cf8037c9491d8f5f9750addb25e))


## v0.6.0 (2026-07-16)

### Bug Fixes

- Address CI + CodeRabbit review on #14
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

- **bake**: Correct packer auth/args, validated by a real bake + canary
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

- **fleet**: Address P0/P1 review blockers
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

- **screener**: Install IMDS guard from the updater so the pet VM is covered
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

### Chores

- Align fleet build timeout with the pet VM (45m lease)
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

### Documentation

- **screener**: Lease expiry is 45m (raised by infra #28)
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

### Features

- Self-bootstrapping fleet instances + label-driven deploys
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

- **fleet**: Golden-image bake mode + packer pipeline
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))

- **screener**: Autoscaled fleet bootstrap, golden image, and IMDS metadata guard
  ([#14](https://github.com/ditto-assistant/ditto-screener/pull/14),
  [`7e0508b`](https://github.com/ditto-assistant/ditto-screener/commit/7e0508b56b1a2d06bafb8189f385c784fbfea748))


## v0.5.6 (2026-07-16)

### Performance Improvements

- Retain 40GB of build cache and parallelize container teardown
  ([#21](https://github.com/ditto-assistant/ditto-screener/pull/21),
  [`c3e8948`](https://github.com/ditto-assistant/ditto-screener/commit/c3e89482a05dfebd24db42b28ddb1b062c400a7c))

- Run the source review concurrently with build, serve, and oracle
  ([#20](https://github.com/ditto-assistant/ditto-screener/pull/20),
  [`41653fc`](https://github.com/ditto-assistant/ditto-screener/commit/41653fceff9951d5d37131ac5fc6470f9b51e6f4))


## v0.5.5 (2026-07-15)

### Bug Fixes

- Send a contract-complete RunRequest from the behavioral oracle
  ([#18](https://github.com/ditto-assistant/ditto-screener/pull/18),
  [`2d53c89`](https://github.com/ditto-assistant/ditto-screener/commit/2d53c898c414aabdc41598b8583cb74dec5c97d1))

### Code Style

- Ruff format ([#18](https://github.com/ditto-assistant/ditto-screener/pull/18),
  [`2d53c89`](https://github.com/ditto-assistant/ditto-screener/commit/2d53c898c414aabdc41598b8583cb74dec5c97d1))


## v0.5.4 (2026-07-15)

### Bug Fixes

- Stop hot-looping inconclusive screens as infrastructure errors
  ([#17](https://github.com/ditto-assistant/ditto-screener/pull/17),
  [`f0c293f`](https://github.com/ditto-assistant/ditto-screener/commit/f0c293f3d0b09d3dcc3fc2e697d5e095f4fb6d6c))


## v0.5.3 (2026-07-15)

### Bug Fixes

- Default build cap to 45m to match the screening lease window
  ([#16](https://github.com/ditto-assistant/ditto-screener/pull/16),
  [`270d6dd`](https://github.com/ditto-assistant/ditto-screener/commit/270d6dd57942ad55c951f3ed4c2690a048e461d1))

- Make screener lease-aware to stop screening-lease-expired loops
  ([#16](https://github.com/ditto-assistant/ditto-screener/pull/16),
  [`270d6dd`](https://github.com/ditto-assistant/ditto-screener/commit/270d6dd57942ad55c951f3ed4c2690a048e461d1))


## v0.5.2 (2026-07-15)

### Bug Fixes

- Resolve _PACKAGE_ROOT from __package__ for python -m execution
  ([#15](https://github.com/ditto-assistant/ditto-screener/pull/15),
  [`3f29016`](https://github.com/ditto-assistant/ditto-screener/commit/3f290161e9dbc2a8455056547f310bb72565d032))

- Restore screener log visibility and stop false rejects on canceled builds
  ([#15](https://github.com/ditto-assistant/ditto-screener/pull/15),
  [`3f29016`](https://github.com/ditto-assistant/ditto-screener/commit/3f290161e9dbc2a8455056547f310bb72565d032))


## v0.5.1 (2026-07-15)

### Bug Fixes

- Bound screener disk growth continuously
  ([#13](https://github.com/ditto-assistant/ditto-screener/pull/13),
  [`637d1f8`](https://github.com/ditto-assistant/ditto-screener/commit/637d1f88bd41f9a1cc0f12a3e2787bfcc14b041b))


## v0.5.0 (2026-07-15)

### Bug Fixes

- Review-hardening for oracle, provenance, and finding integrity
  ([#10](https://github.com/ditto-assistant/ditto-screener/pull/10),
  [`9c81642`](https://github.com/ditto-assistant/ditto-screener/commit/9c816429a0823e85ef99cea787afdfa28b7b01f1))

### Code Style

- Apply ruff format ([#10](https://github.com/ditto-assistant/ditto-screener/pull/10),
  [`9c81642`](https://github.com/ditto-assistant/ditto-screener/commit/9c816429a0823e85ef99cea787afdfa28b7b01f1))

### Features

- Behavioral oracle + quarantine review payloads (policy v8, protocol 0.9.0)
  ([#10](https://github.com/ditto-assistant/ditto-screener/pull/10),
  [`9c81642`](https://github.com/ditto-assistant/ditto-screener/commit/9c816429a0823e85ef99cea787afdfa28b7b01f1))

- Bump screening policy to v8 ([#10](https://github.com/ditto-assistant/ditto-screener/pull/10),
  [`9c81642`](https://github.com/ditto-assistant/ditto-screener/commit/9c816429a0823e85ef99cea787afdfa28b7b01f1))

- **screener**: Behavioral challenge + unfingerprintable gateway
  ([#10](https://github.com/ditto-assistant/ditto-screener/pull/10),
  [`9c81642`](https://github.com/ditto-assistant/ditto-screener/commit/9c816429a0823e85ef99cea787afdfa28b7b01f1))


## v0.4.4 (2026-07-15)

### Bug Fixes

- Target the production screener zone
  ([#12](https://github.com/ditto-assistant/ditto-screener/pull/12),
  [`4a528dd`](https://github.com/ditto-assistant/ditto-screener/commit/4a528ddccea8bd35cd972825ec1e8cbf37518b9f))


## v0.4.3 (2026-07-15)

### Bug Fixes

- Reduce policy v7 source-review false positives
  ([#9](https://github.com/ditto-assistant/ditto-screener/pull/9),
  [`a611623`](https://github.com/ditto-assistant/ditto-screener/commit/a611623a426500af8e295760ed68d67b50206a2c))


## v0.4.2 (2026-07-15)

### Bug Fixes

- Reject exact cross-miner duplicates before screening
  ([#8](https://github.com/ditto-assistant/ditto-screener/pull/8),
  [`14e9ea1`](https://github.com/ditto-assistant/ditto-screener/commit/14e9ea15d12984d8331f16239b4aa5acf98fa836))


## v0.4.1 (2026-07-15)

### Bug Fixes

- Retry interrupted screening builds
  ([#7](https://github.com/ditto-assistant/ditto-screener/pull/7),
  [`6d9372f`](https://github.com/ditto-assistant/ditto-screener/commit/6d9372f761a7597ef90ca2957d2c829d5a1d760f))


## v0.4.0 (2026-07-14)

### Features

- Activate policy v7 Luna screening ([#6](https://github.com/ditto-assistant/ditto-screener/pull/6),
  [`8846b4a`](https://github.com/ditto-assistant/ditto-screener/commit/8846b4adc75d8426909281151e34b50cfa2cbeac))


## v0.3.0 (2026-07-14)

### Features

- Quarantine model-bypass audit anomalies
  ([#4](https://github.com/ditto-assistant/ditto-screener/pull/4),
  [`953b220`](https://github.com/ditto-assistant/ditto-screener/commit/953b2204839291195ca6cc2d468a8888f791b1b7))


## v0.2.0 (2026-07-14)

### Features

- Report privacy-safe screening progress
  ([#5](https://github.com/ditto-assistant/ditto-screener/pull/5),
  [`dc404b3`](https://github.com/ditto-assistant/ditto-screener/commit/dc404b3fd4f9c7bc1062e24670150951c2556c2d))


## v0.1.1 (2026-07-14)

### Bug Fixes

- Install extracted screener systemd unit
  ([#3](https://github.com/ditto-assistant/ditto-screener/pull/3),
  [`d76fbf8`](https://github.com/ditto-assistant/ditto-screener/commit/d76fbf8ce0bd77b332d257c10233821145c50eb9))


## v0.1.0 (2026-07-14)

- Initial Release
