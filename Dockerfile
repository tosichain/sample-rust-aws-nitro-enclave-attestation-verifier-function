FROM rust:alpine3.17 AS build

WORKDIR /aws-template

COPY ./src/ ./src
COPY Cargo.toml ./
COPY Cargo.lock ./

RUN apk add --no-cache musl-dev

RUN apk add perl make

RUN cargo build --release

FROM alpine:3.17

COPY --from=build /aws-template/target/release/aws-template /init