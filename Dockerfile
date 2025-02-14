FROM rust:bookworm AS build

ARG STACKS_NODE_VERSION="No Version Info"
ARG GIT_BRANCH='No Branch Info'
ARG GIT_COMMIT='No Commit Info'

WORKDIR /src

COPY . .

RUN mkdir /out

RUN cargo build --features monitoring_prom,slog_json --release

RUN cp target/release/stacks-node /out

FROM debian:bookworm-slim

COPY --from=build /out/ /bin/

CMD ["stacks-node", "mainnet"]
