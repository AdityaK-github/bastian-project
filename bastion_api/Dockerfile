# Dockerfile for Bastion API Server
FROM rustlang/rust:nightly AS builder

WORKDIR /usr/src/bastion_api

# Copy manifests
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Build for release
RUN cargo build --release

# Runtime stage - use a smaller base image
FROM debian:bookworm-slim

# Install required runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /usr/src/bastion_api/target/release/bastion_api /usr/local/bin/bastion_api

# Set environment variables
ENV RUST_LOG=info

# Expose port
EXPOSE 8080

# Run the binary
CMD ["bastion_api"]
