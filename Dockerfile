# Stage 1: Build the Go application
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download Go modules
RUN go mod download

# Copy the entire project
COPY . .

# Build the application for the cmd/openpons-gateway
# Statically linked binary to run in a minimal image
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /openpons-gateway ./cmd/openpons-gateway

# Stage 2: Create the final image with the compiled binary
FROM alpine:latest

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /openpons-gateway /openpons-gateway

# Expose any necessary ports (e.g., Admin API, xDS server)
# EXPOSE 8080 18000

# Set the entrypoint for the container
ENTRYPOINT ["/openpons-gateway"]
