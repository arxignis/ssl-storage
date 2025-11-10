ARG IMAGE="debian"
ARG IMAGE_TAG="13"

FROM ${IMAGE}:${IMAGE_TAG} AS builder

RUN apt-get update && apt-get install -y git build-essential curl libssl3 ca-certificates libssl-dev pkg-config libzstd-dev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
  . "$HOME/.cargo/env"  && \
  rustup default stable && \
  rustup update stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /app/target/release/ssl-storage /usr/local/bin/ssl-storage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/lib/*/libzstd.so.1 /usr/lib/

ENTRYPOINT ["/usr/local/bin/ssl-storage"]
