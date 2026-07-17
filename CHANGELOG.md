# CHANGELOG

<!-- version list -->

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
