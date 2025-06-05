# Contributing to OpenPons Gateway

First off, thank you for considering contributing to OpenPons Gateway! We welcome any contributions that help improve the project, whether it's reporting a bug, proposing a new feature, improving documentation, or writing code.

This document provides guidelines for contributing to the project.

## Code of Conduct

This project and everyone participating in it is governed by the [OpenPons Gateway Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [project-maintainers@example.com](mailto:project-maintainers@example.com) (replace with actual contact).

## How Can I Contribute?

*   **Reporting Bugs:** If you find a bug, please open an issue in our [issue tracker](https://github.com/openpons/gateway/issues) (replace with actual link). Use the "Bug Report" template if available.
*   **Suggesting Enhancements:** If you have an idea for a new feature or an improvement to an existing one, open an issue using the "Feature Request" template.
*   **Pull Requests:** We welcome pull requests for bug fixes, new features, and improvements.
*   **Documentation:** Improvements to documentation are always welcome.
*   **Community Support:** Help answer questions in GitHub Discussions or other community channels.

## Development Setup

1.  **Prerequisites:**
    *   Go (version specified in `go.mod`, e.g., 1.22 or later)
    *   Docker & Docker Compose (for running dependencies or end-to-end tests)
    *   `protoc` compiler and Go gRPC plugins (`protoc-gen-go`, `protoc-gen-go-grpc`) if you plan to modify `.proto` files.
    *   Make (optional, for using Makefile targets)

2.  **Fork & Clone:**
    *   Fork the repository on GitHub.
    *   Clone your fork locally: `git clone https://github.com/YOUR_USERNAME/gateway.git`
    *   Add the upstream repository: `git remote add upstream https://github.com/openpons/gateway.git`

3.  **Build:**
    *   Navigate to the project root: `cd gateway`
    *   Build the main gateway binary: `go build -o ./bin/openpons-gateway ./cmd/openponsd/`
    *   (If a Makefile is present): `make build`

4.  **Dependencies:**
    *   Go modules are used for dependency management. Run `go mod tidy` to ensure dependencies are clean.

## Coding Style & Guidelines

*   **Formatting:** All Go code must be formatted with `gofmt`. We recommend setting up your editor to run `gofmt` on save. The CI pipeline will check for formatting.
*   **Linting:** We use `golangci-lint` for linting. Please run it locally before submitting a PR. Configuration for `golangci-lint` can be found in `.golangci.yml` (if present).
    ```bash
    # Install golangci-lint if you haven't already
    # See: https://golangci-lint.run/usage/install/
    golangci-lint run
    ```
*   **Vetting:** Always run `go vet ./...` to catch common issues.
*   **Documentation:**
    *   All exported Go functions, types, and variables must have clear GoDoc comments.
    *   Update relevant documentation (README, Outline site, API specs) if your changes affect user-facing behavior or configuration.
*   **Error Handling:** Handle errors gracefully. Use `fmt.Errorf` with `%w` to wrap errors for context.
*   **Logging:** Use the project's structured logger (to be defined in `pkg/logging` or `internal/telemetry`). Avoid `fmt.Print` for logging. Do not log sensitive information.

## Testing

*   **Unit Tests:** Write unit tests for new code and ensure existing tests pass. Place tests in `_test.go` files in the same package as the code they test.
*   **Integration Tests:** For features involving multiple components, consider adding integration tests.
*   **Running Tests:**
    ```bash
    go test ./...
    # Run with race detector (highly recommended)
    go test -race ./...
    # Run with coverage
    go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
    ```
*   All tests must pass, including race detector checks, before a PR can be merged.

## Pull Request Process

1.  **Create an Issue:** For significant changes, it's best to open an issue first to discuss the proposed changes.
2.  **Branch:** Create a new branch from the `dev` branch (or `main` if `dev` doesn't exist yet) for your changes: `git checkout -b feature/your-feature-name dev`
3.  **Commit Messages:** Write clear and concise commit messages. Follow conventional commit formats if adopted by the project (e.g., `feat: add new routing strategy`).
4.  **Develop & Test:** Make your changes, write tests, and ensure all checks (fmt, vet, lint, tests) pass locally.
5.  **Update Documentation:** If your changes affect documentation, update it accordingly.
6.  **Rebase & Push:** Keep your branch up-to-date with `upstream/dev` by rebasing:
    ```bash
    git fetch upstream
    git rebase upstream/dev
    git push origin feature/your-feature-name -f
    ```
7.  **Submit Pull Request:** Open a pull request against the `dev` (or `main`) branch of the `openpons/gateway` repository.
    *   Use the Pull Request template.
    *   Clearly describe the changes and link to any relevant issues.
    *   Ensure all CI checks pass.
8.  **Code Review:** Project maintainers will review your PR. Address any feedback promptly.
9.  **CLA/DCO:** Ensure you have signed the Contributor License Agreement (CLA) or adhered to the Developer Certificate of Origin (DCO) as required by the project. This will likely be checked automatically.

## Getting Help

*   **GitHub Discussions:** For questions, ideas, or general discussion.
*   **Issue Tracker:** For bugs and specific feature requests.

Thank you for contributing to OpenPons Gateway!
