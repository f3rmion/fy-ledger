# Dockerfile for building FROST Ledger App
# Based on Ledger's official app builder image

FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest

# Set working directory
WORKDIR /app

# Copy source files
COPY . .

# Build arguments
ARG CURVE=BJJ
ARG TARGET=nanos2

# Environment variables
ENV CURVE=${CURVE}

# Build the app
# TARGET options: nanos, nanox, nanos2 (Nano S+), stax, flex
CMD ["bash", "-c", "make CURVE=${CURVE}"]
