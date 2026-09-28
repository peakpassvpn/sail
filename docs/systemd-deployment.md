# Deploy Sail with systemd

The files in `packaging/systemd/` install an ordinary, unprivileged proxy by
default. They do not create a user, enable or start a service, reload systemd,
or change networking. Those host-administration steps stay explicit.

## Confirmed CLI and lifecycle behavior

The `sail` binary accepts `--config` (`-c`), `--data-dir` (`-D`),
`--cache-dir`, `--profile`, and `--test` (`-T`). The unit runs the same
configuration and path arguments in `ExecStartPre` and `ExecStart`; a failed
`--test` therefore prevents systemd from starting the process.

The current Unix CLI build handles `SIGTERM` and returns from the runtime after
stopping its instance. It does **not** promise to drain active connections.
There is no SIGHUP handler or CLI reload subcommand. Consequently the supplied
unit has `KillSignal=SIGTERM`, but deliberately has no `ExecReload`.

The main checkout does have three different reload building blocks; none is an
`ExecReload` contract:

- `sail::reload` / `RuntimeManager::reload` rebuild DNS, outbounds and routing
  before publishing them. A build failure keeps the previous live state, and
  existing routed connections keep their previous objects.
- An HTTP runtime reload route exists when the API is configured. This unit
  does not enable or call it: its listener and access-control policy are a
  deployment decision, not a safe implicit local control socket.
- `sail --auto-reload` watches the configuration file and invokes the same
  runtime reload. The supplied unit does not enable it, so its operator model
  remains validate then restart.

Inbound resource reload was integrated into `dev` by merge commit `c6d3bc16`.
It extends reload to supported inbound users, certificates and local rule
files, including watched resource files and rollback on invalid replacements.
It does not add SIGHUP, a CLI reload command, or connection draining, so it
does not by itself justify adding `ExecReload`. Existing connections retain
their prior resource generation.

## Files and privilege modes

`sail.service.in` runs as the dedicated `sail:sail` account, has an empty
capability set, uses a private device namespace, and can write only to its
systemd-managed cache directory under `/var/cache/sail`. The example binds a
SOCKS listener only to `127.0.0.1:1080`.

`sail-tun-transparent.conf` is a separate opt-in drop-in for deployments which
create/configure a TUN device or open transparent-proxy sockets. It exposes
`/dev/net/tun` and grants only `CAP_NET_ADMIN` and `CAP_NET_RAW`; it does not
change the service to root. Review whether a particular configuration can drop
`CAP_NET_RAW`. Host route, policy-routing, firewall, and forwarding rules are
outside this packaging and must be managed separately.

The environment example selects these paths:

| Purpose | Path |
| --- | --- |
| configuration | `/etc/sail/config.json` |
| data and relative certificate files | `/etc/sail` |
| runtime cache | `/var/cache/sail` |
| tuning profile | `server` |

The unit assumes the administrator or package manager has created the locked,
non-login `sail` system account and made `/etc/sail` readable by its group.
Do not make secrets world-readable.

## Staged installation

Build Sail first, then use an explicit staging root. This is suitable for
package construction and for reviewing every installed file:

```sh
cargo build -p sail-cli --release -j 2
stage=$(mktemp -d)
packaging/systemd/install.sh \
  --root "$stage" \
  --check-binary ./target/release/sail \
  --service-binary /usr/bin/sail \
  --dry-run
packaging/systemd/install.sh \
  --root "$stage" \
  --check-binary ./target/release/sail \
  --service-binary /usr/bin/sail
find "$stage" -type f -print
```

The included starter configuration is `config.example.json`. Pass
`--config FILE` to stage a real configuration. If the destination already
contains `etc/sail/config.json`, the installer validates and preserves that
file. It also preserves an existing environment file. A different existing
unit or privilege drop-in is an error, never an implicit overwrite. Repeating
the same install is safe. `--mode tun` opts into the capability drop-in.

The installer requires an absolute, existing, non-symlink `--root`, rejects
symlinked destination components, and refuses `/` unless
`--allow-system-root` is also supplied. Configuration validation occurs before
any destination write. Even with the explicit override, the helper never runs
`systemctl`, creates accounts, installs the Sail executable, or edits network
state.

For a real host, first inspect the staged tree. Then create the locked `sail`
account using the host's account-management policy, install the Sail binary at
the `--service-binary` path, and run the helper as an administrator with:

```sh
sudo packaging/systemd/install.sh \
  --root / --allow-system-root \
  --check-binary /usr/bin/sail \
  --service-binary /usr/bin/sail \
  --config /path/to/reviewed-config.json
sudo chgrp sail /etc/sail /etc/sail/config.json /etc/sail/sail.env
sudo chmod 0750 /etc/sail
sudo chmod 0640 /etc/sail/config.json /etc/sail/sail.env
sudo systemctl daemon-reload
sudo systemctl enable --now sail.service
```

After editing the deployed configuration, validate it with the exact service
paths before restarting:

```sh
sudo -u sail /usr/bin/sail \
  --config /etc/sail/config.json \
  --data-dir /etc/sail \
  --cache-dir /var/cache/sail \
  --profile server --test
sudo systemctl restart sail.service
```

A restart stops the old process with `SIGTERM`; it is not connection draining.

The unit leaves standard output and standard error on systemd's default
journal transport. Use `journalctl -u sail.service`; retention, compression,
size limits, and rotation belong in the host's `journald.conf` policy. The unit
does not create an unrotated application log file.

## Safe removal

The uninstaller reads the install manifest and removes only recorded files
whose hashes are unchanged. Modified files and `/etc/sail/config.json` are
preserved, and directories are never recursively deleted. It is idempotent.
Preview it first:

```sh
packaging/systemd/uninstall.sh --root "$stage" --dry-run
packaging/systemd/uninstall.sh --root "$stage"
```

On a real host, stop/disable the service explicitly before uninstalling, then
run `systemctl daemon-reload`. The helper intentionally does neither.

## Verification

Run the portable checks on any POSIX host:

```sh
packaging/systemd/verify.sh
```

They exercise dry-run immutability, unsafe-target rejection, validation failure
blocking, repeated installation/removal, config preservation, privilege
separation, and the absence of unsupported reload behavior in temporary
directories only.

On any Linux environment, even one without systemd, the evidence-path
self-test can exercise successful and deliberately failed static-analysis
orchestration with a stub analyzer:

```sh
packaging/systemd/acceptance-static-selftest.sh
```

This validates exit-code and failure-phase retention; it is not a substitute
for `systemd-analyze` or a systemd PID 1 lifecycle test.

On a Linux host with `systemd-analyze`, run the non-invasive target-version
unit check. It does not install or start anything:

```sh
packaging/systemd/acceptance-linux.sh \
  --sail-binary /absolute/path/to/sail \
  --artifacts /absolute/path/to/acceptance-artifacts
```

Full lifecycle acceptance is intentionally gated. Use only a disposable VM or
container with systemd as PID 1, no shared production network, an existing
non-root `sail` account, a Sail binary under `/usr` or `/opt` (not a home
directory hidden by `ProtectHome`), an absolute artifact directory, and the
explicit marker:

```sh
printf '%s\n' disposable-system >/run/sail-systemd-acceptance-allowed
packaging/systemd/acceptance-linux.sh \
  --execute-in-disposable-system \
  --sail-binary /absolute/path/to/sail \
  --artifacts /absolute/path/to/acceptance-artifacts
```

The script creates a uniquely named unit under `/run/systemd/system`, validates
the real config, checks non-root/no-capability execution, journald output,
failed-process restart, normal stop, and invalid-config rejection, then removes
the transient unit and cache. It never changes routes or firewall state. Every
exit, including a failed intermediate step, records `result`, `scope`,
`exit_code` and `last_step` and copies all evidence available before cleanup. Runtime mode
refuses to start without `--artifacts`.

TUN capability acceptance is separate and opt-in:

```sh
packaging/systemd/acceptance-linux.sh \
  --execute-in-disposable-system --tun-capability-check \
  --sail-binary /absolute/path/to/sail \
  --artifacts /absolute/path/to/acceptance-artifacts
```

That check verifies a non-root process receives exactly `CAP_NET_ADMIN` and
`CAP_NET_RAW`; it still does not create a TUN device or change networking.
Record the environment, commands, exit codes and evidence using
`packaging/systemd/acceptance-results-template.md`.

macOS and non-systemd Linux hosts can run only `verify.sh`. Production
acceptance must use results from the exact target systemd release rather than
substituting portable checks for a real service lifecycle.

The repository's latest local static evidence is recorded under
`packaging/systemd/validation/`; it deliberately marks real systemd lifecycle
checks as not run.

## Remaining core gaps

Roadmap 4.3 is not complete from packaging alone. Atomic failure rollback
exists for DNS, outbound, routing and supported inbound-resource reloads. The
remaining systemd-facing gaps are (1) a documented, secured operator command
or signal for explicit reload and (2) bounded graceful shutdown which stops
accepting new work and waits for active connections to drain. Only after the
first exists can the unit add a truthful `ExecReload`; only after the second
exists can `TimeoutStopSec` represent a drain bound.
