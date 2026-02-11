FROM rust:1.90-bullseye  AS builder

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./
COPY crates/mydata-proxy crates/mydata-proxy

COPY docker/mydata-proxy/local-test/metrics-generator docker/mydata-proxy/local-test/metrics-generator
RUN cd docker/mydata-proxy/local-test/metrics-generator && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3

COPY --from=builder /usr/src/app/docker/mydata-proxy/local-test/metrics-generator/target/release/metrics-generator /usr/local/bin/metrics-generator

EXPOSE 8000
CMD ["metrics-generator"] 