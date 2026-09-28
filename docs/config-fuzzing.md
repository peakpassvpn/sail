# Parser fuzzing

`fuzz-config/` is an independent cargo-fuzz workspace for untrusted parser
input. It deliberately uses only pure, in-memory entry points:

- `config_json` calls `sail::config::Config::from_json`, covering the currently
  supported sing-box JSON/JSONC parser, schema conversion, unsupported-field
  filtering, defaults, and validation.
- `config_auto` calls `sail::config::from_string`, adding content-based format
  detection. Clash-like and Surge-like inputs currently exercise their clean
  unsupported-format errors; sail does not parse those formats yet.
- `subscription` calls `sail::config::share_link::parse_subscription`, covering
  whole-body base64 decoding, per-line share-link parsing, warning generation,
  and duplicate-tag allocation.
- `rule_set_source` and `rule_set_binary` cover sing-box source JSON and binary
  `.srs` import, including decompression and the bounded binary reader.
- `dns_message` covers raw DNS queries and two-byte stream framing.
- `sniff` covers every stream and datagram traffic sniffer, including QUIC.
- `protocol_inbound` covers the synchronous TUIC and XUDP wire decoders used by
  inbound sessions.

None of the targets reads a file, constructs or starts a proxy instance, binds a
socket, or performs network access. Parser errors are expected results. A panic,
abort, sanitizer finding, or excessive resource use is the failure signal.

## Bounds and corpus

The harness ignores inputs larger than 256 KiB; `sniff` uses the runtime's
16 KiB sniff limit. The general byte limit also bounds the
maximum possible container depth and token count, without pre-empting the JSON
parser's own recursion and high-fan-out handling. Earlier depth/token filters
were intentionally removed because they skipped precisely the extreme parser
boundaries this target is meant to exercise. Non-UTF-8 bytes are ignored because
the public API accepts `&str`; mutations of the committed UTF-8 corpus still
explore arbitrary valid Unicode and malformed JSON/JSONC.

The committed corpus is synthetic and contains no credentials, certificates,
user data, or production rules. It covers valid JSONC, schema and validation
errors, nested logical rules, truncated input, subscription text, rule-set
headers, DNS-like data, sniffable traffic, and inbound frames. Stable tests also
exercise an existing valid `.srs` fixture. `config.dict` provides JSON/JSONC and
schema tokens without embedding real configuration.

## Repeatable commands

Run the stable regression smoke test first:

```sh
cargo test --manifest-path fuzz-config/Cargo.toml -j 2
```

Build every fuzz target from the repository root:

```sh
env CARGO_BUILD_JOBS=2 cargo +nightly fuzz build --fuzz-dir fuzz-config
```

Run a bounded ASan smoke campaign across all targets with reviewed corpus
copies (30 seconds per target):

```sh
fuzz-config/scripts/campaign.sh 30
```

The temporary copies keep a smoke run from adding coverage-generated files to
the reviewed seed corpus. libFuzzer's normal crash artifacts still go under
`fuzz-config/artifacts/<target>/`. cargo-fuzz enables AddressSanitizer by
default; pass `--sanitizer` explicitly when validating with another sanitizer.

For a repeatable sequential campaign (15 minutes per target by default, one
worker, explicit AddressSanitizer and fixed seeds):

```sh
fuzz-config/scripts/campaign.sh
```

Pass another duration in seconds as the first argument. Evidence is retained
under `fuzz-config/evidence/<UTC run id>/`. The script removes its temporary
corpus only after all selected targets exit successfully; on failure it preserves the
scratch corpus and points to the artifact directory.

To run one target independently, pass it as the second argument:

```sh
fuzz-config/scripts/campaign.sh 900 rule_set_binary
```

For a longer local campaign, increase `-max_total_time`; keep `-max_len` aligned
with the harness cap. Replay a finding by putting the artifact path after the
target name and omitting the corpus path and time limit:

```sh
cargo +nightly fuzz run --fuzz-dir fuzz-config config_json fuzz-config/artifacts/config_json/crash-...
```

The checked-in replay helper uses the same ASan, input, and per-input timeout
settings:

```sh
fuzz-config/scripts/replay.sh config_json fuzz-config/artifacts/config_json/crash-...
```

Before minimizing, copy the only artifact to a durable
`fuzz-config/regressions/<target>/` path, then minimize that copy:

```sh
cargo +nightly fuzz tmin --sanitizer address --fuzz-dir fuzz-config config_json fuzz-config/regressions/config_json/case.input
```

Do not pass `-max_len` to `tmin`: with the currently installed libFuzzer it
conflicts with the minimizer's internally selected maximum and aborts inside
libFuzzer rather than minimizing the target crash.

## Known regression and campaign evidence

The 2026-09-28 campaign found a public-parser panic on an overflowing duration.
The original and minimized inputs, hashes, replay command, and suggested core
fix are in `fuzz-config/regressions/config_json/README.md`. The parser fix uses
checked float conversion and checked multi-component accumulation. The stable
regression runs by default and checks that the public parser returns an
invalid-duration error.

Exact campaign metrics and links to the retained raw logs are recorded in
`fuzz-config/evidence/2026-09-28-campaign-report.md`. The `config_json` run was
bounded at 15 minutes but stopped after 144 seconds on the panic; `config_auto`
completed its 15-minute budget without another observed failure. Neither result
is a claim that longer fuzzing would find no additional defect.

Artifacts and build/coverage output are ignored. Corpus improvements should be
reviewed for secrets before they are committed.

The stable test also parses deliberately nonexistent certificate/rule-set paths
and a loopback URL. Success confirms that these public parsing calls only retain
the strings: they do not load files, download rules, or start runtime resources.
