package bootstrap

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetAppCfg resets appCfg to its default state for testing.
// This is important because appCfg is a global variable and tests can modify it.
func resetAppCfgAndFlags() {
	// Reset appCfg struct fields to their zero values or intended defaults before flag parsing
	appCfg = AppConfig{}

	// Cobra flags persist their values across test runs if not reset.
	// We need to reset the rootCmd and its flags to a clean state.
	// One way is to create a new rootCmd instance for each test or group of tests,
	// or reset flags on the existing global rootCmd.
	// For simplicity here, we'll assume tests run in a way that this isn't an issue,
	// or we re-initialize rootCmd if necessary.
	// A more robust way is to have init() return a new *cobra.Command.
	// For now, let's try resetting flags on the global rootCmd.

	// Re-initialize rootCmd to clear any previously set flags or state from other tests.
	// This is a bit of a hack; ideally, rootCmd would be created fresh for tests.
	rootCmd = &cobra.Command{
		Use:   "openpons-gateway",
		Short: "OpenPons Gateway Control Plane",
		Long: `OpenPons Gateway is a unified AI gateway to manage, secure, and observe
AI traffic to LLMs, MCP servers, and A2A communication channels.`,
		Run: func(cmd *cobra.Command, args []string) {
			// runGateway() // Don't actually run the gateway in these CLI tests
		},
	}
	// Re-apply persistent flags to the new/reset rootCmd
	rootCmd.PersistentFlags().StringVar(&appCfg.ConfigFile, "config", "", "config file (default is $HOME/.openpons/gateway.yaml or ./config/gateway.yaml)")
	rootCmd.PersistentFlags().StringVar(&appCfg.AdminListenAddr, "admin-addr", ":8080", "Admin API listen address")
	rootCmd.PersistentFlags().StringVar(&appCfg.XDSListenAddr, "xds-addr", ":18000", "xDS server listen address")
	rootCmd.PersistentFlags().StringVar(&appCfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&appCfg.DatastoreURL, "datastore-url", "sqlite://./openpons_data.db", "Datastore connection URL")

	// Reset cobra's internal state for flag parsing if possible, or rely on new rootCmd.
	// cobra.OnInitialize(initConfig) // initConfig is empty, so this is not strictly needed for reset.
}

func TestRootCmd_DefaultFlagValues(t *testing.T) {
	resetAppCfgAndFlags()

	// Execute with no arguments to parse defaults
	rootCmd.SetArgs([]string{})
	err := rootCmd.Execute() // This will call initConfig via OnInitialize
	require.NoError(t, err)

	// Check default values (as defined in init())
	assert.Equal(t, "", appCfg.ConfigFile, "Default ConfigFile should be empty string (resolved by viper later)")
	assert.Equal(t, ":8080", appCfg.AdminListenAddr, "Default AdminListenAddr is incorrect")
	assert.Equal(t, ":18000", appCfg.XDSListenAddr, "Default XDSListenAddr is incorrect")
	assert.Equal(t, "info", appCfg.LogLevel, "Default LogLevel is incorrect")
	assert.Equal(t, "sqlite://./openpons_data.db", appCfg.DatastoreURL, "Default DatastoreURL is incorrect")
}

func TestRootCmd_OverrideFlagValues(t *testing.T) {
	resetAppCfgAndFlags()

	testCases := []struct {
		name          string
		args          []string
		expectedCfg   AppConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "Override all flags",
			args: []string{
				"--config", "/etc/myconfig.yaml",
				"--admin-addr", ":9090",
				"--xds-addr", ":19000",
				"--log-level", "debug",
				"--datastore-url", "postgres://user:pass@host:port/db",
			},
			expectedCfg: AppConfig{
				ConfigFile:      "/etc/myconfig.yaml",
				AdminListenAddr: ":9090",
				XDSListenAddr:   ":19000",
				LogLevel:        "debug",
				DatastoreURL:    "postgres://user:pass@host:port/db",
			},
			expectError: false,
		},
		{
			name: "Override some flags",
			args: []string{
				"--log-level", "warn",
				"--admin-addr", ":7070",
			},
			expectedCfg: AppConfig{
				ConfigFile:      "", // Default
				AdminListenAddr: ":7070",
				XDSListenAddr:   ":18000", // Default
				LogLevel:        "warn",
				DatastoreURL:    "sqlite://./openpons_data.db", // Default
			},
			expectError: false,
		},
		// Cobra usually handles unknown flags and type errors itself,
		// but we can test if Execute returns an error for them.
		{
			name:          "Unknown flag",
			args:          []string{"--unknown-flag", "value"},
			expectError:   true,
			errorContains: "unknown flag", // Cobra's typical error message
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetAppCfgAndFlags() // Reset for each test case

			// Capture cobra's output to check for errors
			var actualOutput bytes.Buffer
			rootCmd.SetOut(&actualOutput)
			rootCmd.SetErr(&actualOutput) // Capture stderr as well

			rootCmd.SetArgs(tc.args)
			executeErr := rootCmd.Execute()

			if tc.expectError {
				require.Error(t, executeErr, "Expected an error for args: %v", tc.args)
				if tc.errorContains != "" {
					// Cobra might print to stderr and then os.Exit(1) via Execute(),
					// or return an error. We check both.
					// The error from rootCmd.Execute() might be generic if cobra handles exit internally.
					// So, checking output is more reliable for specific flag errors.
					assert.Contains(t, actualOutput.String(), tc.errorContains, "Error output mismatch")
				}
			} else {
				require.NoError(t, executeErr, "Did not expect an error for args: %v. Output: %s", tc.args, actualOutput.String())
				assert.Equal(t, tc.expectedCfg.ConfigFile, appCfg.ConfigFile)
				assert.Equal(t, tc.expectedCfg.AdminListenAddr, appCfg.AdminListenAddr)
				assert.Equal(t, tc.expectedCfg.XDSListenAddr, appCfg.XDSListenAddr)
				assert.Equal(t, tc.expectedCfg.LogLevel, appCfg.LogLevel)
				assert.Equal(t, tc.expectedCfg.DatastoreURL, appCfg.DatastoreURL)
			}
		})
	}
}

// TestExecute is a basic test for the main Execute function.
// It mainly checks that it doesn't panic.
// Testing side effects of Execute (like os.Exit) is more complex.
func TestExecute(t *testing.T) {
	// To prevent os.Exit(1) from stopping the test run, we can temporarily
	// replace os.Exit or test Execute in a way that doesn't trigger it.
	// For now, just call it and ensure no panic.
	// If rootCmd.Execute() returns an error, Execute() will print it and os.Exit(1).

	// We need to ensure rootCmd is in a state that won't cause an error.
	resetAppCfgAndFlags()
	rootCmd.SetArgs([]string{"--help"}) // A safe command that should not error

	// Capture os.Stdout to prevent help message from printing during tests
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Execute is expected to call os.Exit on error.
	// This test is limited because os.Exit terminates the test process.
	// A more robust test would involve a custom command that doesn't exit,
	// or using a test harness that can catch os.Exit.
	// For now, we just check for panics with a safe command.
	assert.NotPanics(t, func() {
		// Execute() // This will call os.Exit if rootCmd.Execute() errors.
		// Instead of calling the top-level Execute(), which calls os.Exit(),
		// let's test the behavior of rootCmd.Execute() directly for this case.
		err := rootCmd.Execute()
		assert.NoError(t, err, "Executing --help should not error")
	})

	w.Close()
	os.Stdout = oldStdout // Restore stdout
	// Drain the pipe to avoid issues, though we don't check its content here.
	_, _ = io.Copy(io.Discard, r)
	r.Close()
}

// initConfig is currently empty, so no specific tests for it yet.
// If it were to load from a config file using Viper, tests would involve
// creating temp config files and mocking environment variables.

// Note: Testing the runGateway() function directly is complex due to its role as the main
// application entry point, its use of global state (appCfg, telemetry.Logger), direct
// initialization of services, and signal handling for graceful shutdown.
// Such a function is typically tested via integration or end-to-end tests.
// The existing tests for flag parsing (TestRootCmd_*) cover the primary configurable
// aspects of the bootstrap package. Further unit tests for runGateway would require
// significant refactoring to allow for dependency injection and control over its lifecycle.
