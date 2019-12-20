FROM wglozer/xcc:base

ARG TARGET=x86_64-linux-musl
ARG TOOLCHAIN=1.39.0

ENV PATH="/root/.cargo/bin:/opt/xcc/${TARGET}/bin:${PATH}"
ENV PKG_CONFIG_PATH=/opt/xcc/${TARGET}/lib/pkgconfig
ENV CC=${TARGET}-cc
ENV CXX=${TARGET}-c++

RUN apt-get update && apt-get install -y git rpm

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path --default-toolchain none

RUN rustup toolchain add ${TOOLCHAIN}
RUN rustup default       ${TOOLCHAIN}
RUN rustup target    add x86_64-unknown-linux-musl

RUN cargo install cargo-deb cargo-rpm

ADD build/cargo/config /root/.cargo/config

CMD bash
