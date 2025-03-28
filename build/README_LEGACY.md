# kprobe build setup

kprobe is distributed as a static binary linked with musl libc which
requires a proper cross compilation environment. A reproducible
build environment can be created using docker:

```
docker build -t kprobe-build -f build/Dockerfile .
docker run --rm -ti -v $PWD:/work -v $HOME/.ssh:/root/.ssh kprobe-build bash
root@d798d406bab1:/work# cargo build --release --target x86_64-unknown-linux-musl
```

Public releases include .deb and .rpm packages which can be built
inside the same docker container:

```
root@d798d406bab1:/work# build/build.sh
```

kprobe depends on private github.com/kentik repositories that require
SSH authentication, so a GitHub deploy key, a developer's key, or a
SSH agent socket must be volume mounted into the build container.

# macOS dev setup

Static x86_64 linux binaries can be built on macOS by installing
the `musl-cross` homebrew package and adding the following lines to
~/.cargo/config:

```
[target.x86_64-unknown-linux-musl]
ar     = "x86_64-linux-musl-ar"
linker = "x86_64-linux-musl-gcc"
```

```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

# binary dependencies

Building kprobe is complicated, primarily because it is delivered as
static binaries. This requires linking to static versions of libpcap
and libkflow, which in turn must be built against musl libc.

Additionally the Go runtime must be [patched][runtime-patch] so that
it doesn't crash when linked into a static binary, so a customized
build of the Go toolchain must be used to compile libkflow.

Instead of building these dependencies during the kprobe build, binary
versions are checked in under `libs/`. The [kprobe-libs][kprobe-libs]
repository contains a reproducible configuration for building Linux
versions of these libraries.


[kprobe-libs]: https://github.com/kentik/kprobe-libs

[runtime-patch]: https://github.com/kentik/kprobe-libs/blob/master/go-runtime.patch
