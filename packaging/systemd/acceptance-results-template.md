# Sail systemd acceptance result

- Date (UTC):
- Tester:
- Host/VM identifier:
- Distribution and systemd version:
- Kernel and architecture:
- Sail commit and `sail -V`:
- Ordinary or TUN opt-in mode:
- Artifact directory:

## Preconditions

- [ ] Disposable, isolated Linux environment; not a production host
- [ ] PID 1 is systemd
- [ ] Dedicated non-root `sail` account exists
- [ ] Sail binary and configuration are readable/executable by that account
- [ ] No host networking, routes, firewall, or production services are shared
- [ ] `/run/sail-systemd-acceptance-allowed` contains `disposable-system`

## Commands and exit codes

| Command | Exit | Evidence |
| --- | ---: | --- |
| `packaging/systemd/verify.sh` | | |
| `systemd-analyze verify …/sail-acceptance-….service` | | `systemd-analyze-verify.txt` |
| `systemd-analyze verify …/sail-acceptance-tun-….service` | | `systemd-analyze-verify-tun.txt` |
| `acceptance-linux.sh --execute-in-disposable-system …` | | `result.txt` |

## Ordinary proxy checks

| Check | Pass/Fail | Evidence or observation |
| --- | --- | --- |
| Unit parses on the target systemd version | | |
| Valid configuration passes `sail --test` | | |
| Service runs as non-root `sail` UID | | `systemctl-show.txt` |
| Base capability set is empty | | rendered unit |
| Logs reach journald | | `journal.txt` |
| `SIGKILL` failure is restarted | | `NRestarts` in `systemctl-show.txt` |
| Normal stop exits under the unit's `SIGTERM` policy | | journal and service state |
| Invalid configuration is blocked by `ExecStartPre` | | journal and failed state |
| Dry-run, repeat install, preserve and uninstall checks pass | | `verify.sh` output |

## TUN/transparent opt-in checks

Leave this section `Not run` unless `--tun-capability-check` was explicitly
used in a disposable network namespace or VM.

| Check | Pass/Fail/Not run | Evidence or observation |
| --- | --- | --- |
| Process remains non-root | | `/proc/MAINPID/status` |
| Effective mask is exactly `0x3000` | | `CapEff` (`NET_ADMIN`, `NET_RAW`) |
| `/dev/net/tun` policy is present | | drop-in |
| No routes, firewall rules, or forwarding state were changed | | environment audit |

## Explicitly not proven by this run

- Active-connection draining during shutdown (not implemented).
- SIGHUP or `systemctl reload` behavior (no CLI/signal interface exists).
- Inbound resource hot reload unless the separate implementation has been
  integrated and tested in the exact deployed build.
- Production routing/TUN behavior; that requires a separately authorized
  network-isolated test plan.

## Failures and follow-up

Record the exact failed command, exit code, relevant journal excerpt, retained
artifact path, and the smallest required fix or environment change.
