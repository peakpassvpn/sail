.PHONY: cli cli-dev test proto-gen

CFG_COMMIT_HASH := $(shell git rev-parse HEAD | cut -c 1-7)
export CFG_COMMIT_HASH := $(CFG_COMMIT_HASH)
CFG_COMMIT_DATE := $(shell git log --format="%ci" -n 1)
export CFG_COMMIT_DATE := $(CFG_COMMIT_DATE)

cli:
	cargo build -p sail-cli --release

cli-dev:
	cargo build -p sail-cli

test:
	cargo test -p sail -- --nocapture

proto-gen:
	./scripts/regenerate_proto_files.sh
