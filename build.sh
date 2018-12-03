#!/bin/sh

set -ex

cargo deb --no-strip --target x86_64-unknown-linux-musl
cargo rpm build

cp target/debian/kprobe*.deb .
cp target/release/rpmbuild/RPMS/x86_64/kprobe*.rpm .
