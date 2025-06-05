# OpenPons Gateway

OpenPons Gateway is a unified AI gateway designed to manage, secure, and observe traffic to various Large Language Models (LLMs), Model Context Protocol (MCP) servers, and Agent-to-Agent (A2A) communication channels. This project aims to provide an enterprise-grade, extensible, and security-first solution for AI infrastructure.

**Core Goals:**
*   **Security-first:** TLS 1.3 everywhere, OAuth2/OIDC, mTLS for A2A, Envoy RBAC.
*   **Unified AI traffic:** Support REST (OpenAI-style), gRPC, SSE, A2A, MCP over HTTP/3/QUIC.
*   **Hot-reload config:** Envoy xDS driven by Go control-plane.
*   **Extensibility:** Pre/Post hooks via WASM or ext_proc.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [Running with Docker](#running-with-docker)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Code of Conduct](#code-of-conduct)
- [License](#license)

## Overview

OpenPons Gateway acts as an intermediary layer for all AI-related traffic, providing centralized control, security, and observability. It leverages Envoy as its data plane for high-performance request handling and a Go-based control plane for dynamic configuration and management.

## Features

*   **Protocol Unification:** Proxies OpenAI-style REST APIs, gRPC services, MCP, and A2A protocols.
*   **Dynamic Routing:** Configure routes to different upstream providers with policies for load balancing, retries, and timeouts.
*   **IAM & Security:** Robust authentication (API Keys, OIDC) and authorization (RBAC) for accessing gateway resources and proxied services.
*   **Plugin Framework:** Extend gateway functionality with custom logic at various hook points using out-of-process plugins (e.g., via Hashicorp go-plugin).
*   **Observability:** Exposes Prometheus metrics, supports OpenTelemetry tracing, and provides structured logging.
*   **Dynamic Configuration:** Hot-reloads configuration changes without downtime via xDS.
*   *(More features to be detailed as developed)*

## Architecture

The OpenPons Gateway consists of two main components:
1.  **Control Plane (Go):** Manages configuration, serves the Admin API, implements IAM, manages plugins, and configures the data plane via xDS.
2.  **Data Plane (Envoy Proxy):** Handles all ingress and egress traffic, enforces policies, and executes plugin logic via `ext_proc`.

*(A link to a more detailed architecture diagram, possibly in the /docs folder or the Outline site, will be added here.)*

## Getting Started

### Prerequisites

*   Go 1.22+
*   Docker (for building/running containerized version)
*   `protoc` and Go protobuf/gRPC plugins (for regenerating API types if modifying `.proto` files)
*   *(Other dependencies as they arise)*

### Building from Source

```bash
# Clone the repository
git clone https://github.com/openpons/gateway.git
cd gateway

# Build the openpons-gateway binary
go build -o ./bin/openpons-gateway ./cmd/openpons-gateway/

#### Building with Version Information

To embed version information (like version number, commit hash, and build date) into the binary, use `ldflags` during the build. The `internal/version/version.go` file contains placeholder variables for this purpose.

Example:
```bash
# Get current git commit hash and date
COMMIT_HASH=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
APP_VERSION="0.1.0" # Replace with your desired version

# Define the package path for version variables
VERSION_PKG="github.com/openpons/gateway/internal/version"

# Construct ldflags
LDFLAGS="-X '${VERSION_PKG}.Version=${APP_VERSION}' \
         -X '${VERSION_PKG}.Commit=${COMMIT_HASH}' \
         -X '${VERSION_PKG}.Date=${BUILD_DATE}' \
         -X '${VERSION_PKG}.BuiltBy=$(go version)'"

# Build with ldflags
go build -ldflags="${LDFLAGS}" -o ./bin/openpons-gateway ./cmd/openpons-gateway/
```

**Note:** For this version information to be useful, the application should be updated to display it (e.g., via a `--version` command-line flag or by logging it at startup). Currently, the version variables defined in `internal/version/version.go` are not actively used by the application to display version information.

# (Optional) Build the CLI tool
# go build -o ./bin/openponsctl ./cmd/openponsctl/
```

### Running with Docker

A `Dockerfile` is provided to build a container image.

```bash
# Build the Docker image
docker build -t openpons/gateway:latest .

# Run the Docker container (example, will need configuration)
# docker run -p 8080:8080 -p 10000:10000 openpons/gateway:latest
```
*(More detailed instructions on running with Docker, including volume mounts for configuration, will be added.)*

## Configuration

OpenPons Gateway is configured via a central configuration source (e.g., etcd, Postgres, Redis, or a local YAML/TOML file for simple setups) and managed through its Admin API.

*(Details on configuration structure and management will be added here and in the main documentation.)*

## Usage Examples

*(Basic examples of proxying an LLM request or a tool invocation will be added here.)*

## Documentation

Full and detailed documentation is planned to be available at: **[docs.openpons.com](https://docs.openpons.com)** (Note: The documentation site is under development).

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute, including development setup, coding standards, and the pull request process.

## Code of Conduct

This project adheres to the Contributor Covenant. Please read our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
