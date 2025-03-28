# Building kprobe

Building kprobe is honestly a mess at this point. The streamlined build
processes have not been maintained in years so the required docker images
can no longer be created. The previous build instructions can be found at
the bottom of this document but are not recommended nor guaranteed to work.

# Build Setup

Kprobe is built using the Rust toolchain. The current know working path to
success assumes that builds are done from a recent version of macOS without
the use of any images.

### Setup Rust musl targets

kprobe is distributed as a static binary linked with musl libc which
requires a proper cross compilation environment.

To set this up on macOS:

Install the `musl-cross` homebrew package:

```shell
brew install filosottile/musl-cross/musl-cross
```

Add the following lines to `~/.cargo/config`:
Then, add the following lines to `~/.cargo/config`:

```toml
[target.x86_64-unknown-linux-musl]
ar = "x86_64-linux-musl-ar"
linker = "x86_64-linux-musl-gcc"
```

And add the musl target to rust:

```shell
rustup target add x86_64-unknown-linux-musl
```

### Acquire the static libraries

The static libraries required to build kprobe are assumed to exist in the
`{REPO_ROOT}/libs/` directory. Originally, these libraries were built using
the `kprobe-libs` repository. Unfortunately, the build process outlined in
that repository in no longer functional and new processes must be developed.

At this time only the `libkflow` library has a known working build process.

#### Acquiring a new version of libkflow

Follow the instructions in the `libkflow` repository to build a new set of
internal libraries. Copy the resulting `{LIBKFLOW_REPO_ROOT}/libs/` folder
over `{KPROBE_REPO_ROOT}/libs/` to use the updated library.

Do not forget to committhe updated libraries.

# REALLY BUILDING KPROBE

With all of that setup out of the way building kprobe is straightforward.

## Build for release

```shell
cargo build --release --target x86_64-unknown-linux-musl
```

## Build for local use

```shell
cargo build --release
```

# LEGACY BUILD INSTRUCTIONS
These can be found in [LEGACY README](./README_LEGACY.md). They are not recommended
