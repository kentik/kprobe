#!/bin/sh

set -ex

TARGET=x86_64-unknown-linux-musl

cargo deb --no-strip --target $TARGET -- --bin kprobe
cargo rpm build

cp target/$TARGET/debian/kprobe*.deb .
cp target/release/rpmbuild/RPMS/x86_64/kprobe*.rpm .
