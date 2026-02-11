FROM rust:1.90-bullseye  AS builder

ARG PROFILE=release
WORKDIR /work

RUN apt-get update && apt-get install -y cmake clang ca-certificates curl && update-ca-certificates

COPY .git/ .git/
COPY Cargo.toml Cargo.lock ./
COPY crates/mydata-proxy crates/mydata-proxy

RUN cargo build --profile ${PROFILE} --bin mydata-proxy

FROM debian:bookworm-slim as prod
RUN apt-get update && apt install -y openssl ca-certificates && update-ca-certificates
COPY --from=build --chmod=755 /work/target/release/mydata-proxy /opt/mydata-proxy/bin/mydata-proxy
