FROM rust

COPY . /app
WORKDIR /app
RUN cargo install --path himitsu-precommit