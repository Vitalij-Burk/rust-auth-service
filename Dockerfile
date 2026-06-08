# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.94.0
ARG APP_NAME=rust-auth-service

FROM rust:${RUST_VERSION}-alpine AS chef
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
ARG APP_NAME
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .

RUN cargo build --locked --release && \
    cp ./target/release/${APP_NAME} /bin/${APP_NAME}

FROM alpine:3.18 AS final
ARG APP_NAME=rust-auth-service
WORKDIR /app

COPY --from=build /bin/${APP_NAME} /bin/

EXPOSE 5000

CMD ["/bin/auth"]
