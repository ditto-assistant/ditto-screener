# CHANGELOG

<!-- version list -->

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
