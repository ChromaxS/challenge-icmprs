FROM rust AS base

# Install helpful utilities
RUN apt-get update && apt-get install -y \
  iputils-ping \
  vim \
  traceroute \
  nmap

FROM base AS build

# Build
COPY Cargo.toml /opt
COPY Cargo.lock /opt
COPY src /opt/src/

WORKDIR /opt
RUN cargo build --release

FROM base AS final

# Copy runtime asset
COPY --from=build /opt/target/release/icmprs /opt
# Entry is the program
ENTRYPOINT ["/opt/icmprs"]