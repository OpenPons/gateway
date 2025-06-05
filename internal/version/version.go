// Package version provides build and version information for the OpenPons Gateway.
// This information is typically embedded at build time via ldflags.
package version

// Placeholder variables for version information.
// These can be set at build time using ldflags.
// Example: go build -ldflags "-X github.com/openpons/gateway/internal/version.Version=v1.0.0 -X github.com/openpons/gateway/internal/version.GitCommit=$(git rev-parse HEAD)"
var (
	Version   = "dev"     // Default version for local development
	GitCommit = "unknown" // Git commit SHA
	BuildDate = "unknown" // Build date
)

// Info holds all version information.
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"gitCommit"`
	BuildDate string `json:"buildDate"`
}

// Get returns the version information.
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
	}
}
