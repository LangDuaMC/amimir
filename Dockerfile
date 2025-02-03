FROM rust:latest as builder

WORKDIR /usr/src
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() { println!(\"Dummy\"); }" > src/main.rs
RUN cargo build --release

COPY . .
RUN cargo build --target x86_64-unknown-linux-musl --release

FROM alpine:latest
RUN apk add --no-cache musl
COPY --from=builder /usr/src/target/x86_64-unknown-linux-musl/release/* /usr/local/bin
CMD ["myapp"]
