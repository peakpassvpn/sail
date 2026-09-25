#!/usr/bin/env sh

set -ex

touch sail/build.rs
PROTO_GEN=1 cargo build -p sail
