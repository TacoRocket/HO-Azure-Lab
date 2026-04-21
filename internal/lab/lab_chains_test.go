package lab

import (
	"slices"
	"testing"
)

func TestValidateCredentialPathPayloadAgainstAzureContextPassesForExpectedRows(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "credential-path", Viewpoint: "admin"}
	payload := map[string]any{
		"paths": []any{
			map[string]any{
				"asset_id":          "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/func-orders",
				"asset_name":        "func-orders",
				"asset_kind":        "FunctionApp",
				"setting_name":      "PAYMENT_API_KEY",
				"target_service":    "keyvault",
				"target_resolution": "named match",
				"target_count":      float64(1),
				"target_names":      []any{"kv-orders"},
				"clue_type":         "keyvault-reference",
				"evidence_commands": []any{"env-vars", "tokens-credentials", "keyvault"},
			},
		},
	}
	envVars := &liveEnvVarsContextArtifact{
		EnvVars: []liveEnvVarTruth{
			{
				AssetID:        "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/func-orders",
				AssetKind:      "FunctionApp",
				AssetName:      "func-orders",
				SettingName:    "PAYMENT_API_KEY",
				ValueType:      "keyvault-ref",
				LooksSensitive: true,
				ReferenceTarget: func() *string {
					value := "https://kv-orders.vault.azure.net/secrets/payment-api-key"
					return &value
				}(),
			},
		},
	}
	tokens := &liveTokensCredentialsContextArtifact{
		ExpectedSurfaces: []liveTokensCredentialSurfaceTruth{
			{AssetID: "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/func-orders"},
		},
	}
	keyVaults := &liveKeyVaultContextArtifact{
		KeyVaults: []liveKeyVaultTruth{{Name: "kv-orders", VaultURI: "https://kv-orders.vault.azure.net/"}},
	}

	findings := validateCredentialPathPayloadAgainstAzureContext(entry, "families credential-path (admin)", payload, envVars, tokens, &liveDatabasesContextArtifact{}, keyVaults, &liveStorageContextArtifact{})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidateCredentialPathPayloadAgainstAzureContextFlagsMissingExpectedRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "credential-path", Viewpoint: "admin"}
	payload := map[string]any{"paths": []any{}}
	envVars := &liveEnvVarsContextArtifact{
		EnvVars: []liveEnvVarTruth{
			{
				AssetID:        "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/func-orders",
				AssetKind:      "FunctionApp",
				AssetName:      "func-orders",
				SettingName:    "PAYMENT_API_KEY",
				ValueType:      "keyvault-ref",
				LooksSensitive: true,
				ReferenceTarget: func() *string {
					value := "https://kv-orders.vault.azure.net/secrets/payment-api-key"
					return &value
				}(),
			},
		},
	}
	tokens := &liveTokensCredentialsContextArtifact{
		ExpectedSurfaces: []liveTokensCredentialSurfaceTruth{
			{AssetID: "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/func-orders"},
		},
	}
	keyVaults := &liveKeyVaultContextArtifact{
		KeyVaults: []liveKeyVaultTruth{{Name: "kv-orders", VaultURI: "https://kv-orders.vault.azure.net/"}},
	}

	findings := validateCredentialPathPayloadAgainstAzureContext(entry, "families credential-path (admin)", payload, envVars, tokens, &liveDatabasesContextArtifact{}, keyVaults, &liveStorageContextArtifact{})
	if len(findings) == 0 {
		t.Fatal("expected a finding for the missing credential-path row")
	}
}

func TestGroupedFamilyTopLevelFieldsForChains(t *testing.T) {
	fields := groupedFamilyTopLevelFields("chains")
	for _, required := range []string{"family", "paths", "issues"} {
		if !slices.Contains(fields, required) {
			t.Fatalf("expected grouped chains family fields to include %q: %#v", required, fields)
		}
	}
	for _, forbidden := range []string{"selected_family", "families"} {
		if slices.Contains(fields, forbidden) {
			t.Fatalf("did not expect grouped chains family fields to include %q: %#v", forbidden, fields)
		}
	}
}
