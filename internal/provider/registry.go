package provider

import (
	"fmt"
	"log"
	"sync"

	// "net/http" // For a shared HTTP client if needed by adapters

	"github.com/openpons/gateway/internal/config"
	"github.com/openpons/gateway/internal/secrets"
	// "github.com/openpons/gateway/internal/secrets" // For fetching API keys
)

// Registry manages and provides access to initialized provider adapters.
type Registry struct {
	mu            sync.RWMutex
	adapters      map[string]ProviderAdapter // providerConfig.ID -> Adapter
	secretManager secrets.SecretManagementService
	// httpClient *http.Client
}

// RegistryInterface defines the methods proxy handlers (and other components)
// need from a provider Registry. This allows for easier mocking in tests.
type RegistryInterface interface {
	GetAdapter(providerID string) (ProviderAdapter, error)
	// Add InitAdapters and Shutdown if needed by components being refactored
}

// NewRegistry creates a new provider adapter registry.
func NewRegistry(sm secrets.SecretManagementService /*, httpClient *http.Client*/) *Registry {
	return &Registry{
		adapters:      make(map[string]ProviderAdapter),
		secretManager: sm,
		// httpClient: httpClient,
	}
}

// InitAdapters initializes adapters based on the provided provider configurations.
// This should be called when the gateway starts or when provider configs change.
func (r *Registry) InitAdapters(providerConfigs []config.ProviderConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear existing adapters or implement more sophisticated update logic
	r.adapters = make(map[string]ProviderAdapter)

	for _, pCfg := range providerConfigs {
		if pCfg.Status != "active" { // Assuming "active" is the status for enabled providers
			log.Printf("Provider %s (%s) is not active, skipping adapter initialization.", pCfg.Name, pCfg.ID)
			continue
		}

		var adapter ProviderAdapter
		var err error

		// Individual adapter constructors (e.g., NewOpenAIAdapter) are responsible for
		// using pCfg.CredentialsSecretID and r.secretManager to fetch credentials.
		// The registry's role is to pass these dependencies.

		switch pCfg.Type {
		case config.ProviderTypeLLM:
			// Attempt to initialize LLM providers in a specific order (e.g., OpenAI, Anthropic, VertexAI)
			// This assumes constructors like NewOpenAIAdapter return an error if the config isn't suitable for them.
			adapter, err = NewOpenAIAdapter(pCfg, r.secretManager, nil)
			if err == nil {
				log.Printf("Initialized OpenAI adapter for LLM provider %s (%s)", pCfg.Name, pCfg.ID)
			} else {
				log.Printf("OpenAI adapter init failed for %s (%s): %v. Trying Anthropic.", pCfg.Name, pCfg.ID, err)
				adapter, err = NewAnthropicAdapter(pCfg, r.secretManager, nil)
				if err == nil {
					log.Printf("Initialized Anthropic adapter for LLM provider %s (%s)", pCfg.Name, pCfg.ID)
				} else {
					log.Printf("Anthropic adapter init failed for %s (%s): %v. Trying VertexAI.", pCfg.Name, pCfg.ID, err)
					adapter, err = NewVertexAIAdapter(pCfg, r.secretManager, nil)
					if err != nil {
						log.Printf("All LLM adapter initializations failed for provider %s (%s): %v. Last error (VertexAI): %v", pCfg.Name, pCfg.ID, err, err)
						continue // Skip this provider if all attempts fail
					}
					log.Printf("Initialized VertexAI adapter for LLM provider %s (%s)", pCfg.Name, pCfg.ID)
				}
			}
		case config.ProviderTypeToolServer:
			adapter, err = NewMCPToolAdapter(pCfg, r.secretManager, nil)
			if err != nil {
				log.Printf("Error initializing MCP Tool Server adapter for %s (%s): %v", pCfg.Name, pCfg.ID, err)
				continue
			}
		case config.ProviderTypeAgentPlatform:
			adapter, err = NewA2APlatformAdapter(pCfg, r.secretManager, nil)
			if err != nil {
				log.Printf("Error initializing A2A Platform adapter for %s (%s): %v", pCfg.Name, pCfg.ID, err)
				continue
			}
		default:
			log.Printf("Unknown or unsupported provider type '%s' for provider %s (%s)", pCfg.Type, pCfg.Name, pCfg.ID)
			continue
		}

		// If adapter is successfully created (err was nil from one of the attempts)
		if adapter != nil { // This check is now more crucial as err might be from a failed attempt but adapter non-nil from a success
			// Call Init on the adapter as per the ProviderAdapter interface contract
			if initErr := adapter.Init(&pCfg, r.secretManager); initErr != nil {
				log.Printf("Error re-initializing adapter for provider %s (%s) during registry InitAdapters: %v", pCfg.Name, pCfg.ID, initErr)
				continue // Skip this adapter if Init fails
			}
			r.adapters[pCfg.ID] = adapter
			info := adapter.ProviderInfo()
			// ID comes from the config, which the adapter should now store/return via GetConfig()
			log.Printf("Initialized adapter for provider: %s (ID: %s, Type: %s)", info.Name, adapter.GetConfig().ID, info.Type)
		}
	}
}

// GetAdapter retrieves an initialized adapter by its provider configuration ID.
func (r *Registry) GetAdapter(providerID string) (ProviderAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, exists := r.adapters[providerID]
	if !exists {
		return nil, fmt.Errorf("no active adapter found for provider ID: %s", providerID)
	}
	return adapter, nil
}

// Shutdown closes all managed adapters.
func (r *Registry) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	log.Println("Shutting down all provider adapters...")
	for id, adapter := range r.adapters {
		if err := adapter.Shutdown(); err != nil {
			log.Printf("Error shutting down adapter for provider %s: %v", id, err)
		}
	}
	r.adapters = make(map[string]ProviderAdapter) // Clear map
	log.Println("All provider adapters shut down.")
}
