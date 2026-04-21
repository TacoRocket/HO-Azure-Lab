package lab

import "testing"

func TestValidateComputeControlPayloadAgainstAzureContextPassesForCanaryRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "compute-control", Viewpoint: "admin"}
	payload := map[string]any{
		"paths": []any{
			map[string]any{
				"asset_id":          "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-uami-ctrl",
				"asset_name":        "app-uami-ctrl",
				"asset_kind":        "AppService",
				"source_command":    "tokens-credentials",
				"clue_type":         "managed-identity-token",
				"target_service":    "azure-control",
				"target_resolution": "path-confirmed",
				"target_count":      float64(1),
				"target_ids":        []any{"/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
				"target_names":      []any{"ua-app"},
				"evidence_commands": []any{"tokens-credentials", "workloads", "managed-identities", "permissions"},
			},
		},
	}
	context := &liveComputeControlContextArtifact{
		Canary: &liveComputeControlCanaryRow{
			AssetID:          "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-uami-ctrl",
			AssetName:        "app-uami-ctrl",
			AssetKind:        "AppService",
			IdentityID:       "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app",
			IdentityName:     "ua-app",
			TargetResolution: "path-confirmed",
			RequiredEvidence: []string{"tokens-credentials", "workloads", "managed-identities", "permissions"},
		},
	}

	findings := validateComputeControlPayloadAgainstAzureContext(entry, "families compute-control (admin)", payload, context)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidateComputeControlPayloadAgainstAzureContextFlagsUnexpectedRowsWhenZeroExpected(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "compute-control", Viewpoint: "dev"}
	payload := map[string]any{
		"paths": []any{
			map[string]any{
				"asset_id":       "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-uami-ctrl",
				"target_service": "azure-control",
				"target_ids":     []any{"/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
			},
		},
	}
	context := &liveComputeControlContextArtifact{ExpectZeroRows: true}

	findings := validateComputeControlPayloadAgainstAzureContext(entry, "families compute-control (dev)", payload, context)
	if len(findings) == 0 {
		t.Fatal("expected a finding for unexpected compute-control rows when zero rows are defended")
	}
}

func TestValidateComputeControlPayloadAgainstAzureContextRequiresExplicitIssueForVisibilityBlockedZeroRows(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "compute-control", Viewpoint: "lower-privilege"}
	payload := map[string]any{
		"paths":  []any{},
		"issues": []any{},
	}
	context := &liveComputeControlContextArtifact{
		ExpectZeroRows:          true,
		ZeroRowReason:           "visibility_blocked",
		RequiredIssueCollectors: []string{"env_vars[rg-workload/app-uami-ctrl]"},
	}

	findings := validateComputeControlPayloadAgainstAzureContext(entry, "families compute-control (lower-privilege)", payload, context)
	if len(findings) == 0 {
		t.Fatal("expected a finding when visibility-blocked zero-row compute-control output does not carry the expected collection_error issue")
	}
}

func TestValidateComputeControlPayloadAgainstAzureContextAllowsExplicitVisibilityBlockedZeroRows(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "compute-control", Viewpoint: "lower-privilege"}
	payload := map[string]any{
		"paths": []any{},
		"issues": []any{
			map[string]any{
				"kind":  "collection_error",
				"scope": "env_vars[rg-workload/app-uami-ctrl]",
			},
		},
	}
	context := &liveComputeControlContextArtifact{
		ExpectZeroRows:          true,
		ZeroRowReason:           "visibility_blocked",
		RequiredIssueCollectors: []string{"env_vars[rg-workload/app-uami-ctrl]"},
	}

	findings := validateComputeControlPayloadAgainstAzureContext(entry, "families compute-control (lower-privilege)", payload, context)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for explicit visibility-blocked zero-row compute-control output, got %#v", findings)
	}
}

func TestValidateComputeControlPayloadAgainstAzureContextFlagsMissingCanaryRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "compute-control", Viewpoint: "admin"}
	payload := map[string]any{"paths": []any{}}
	context := &liveComputeControlContextArtifact{
		Canary: &liveComputeControlCanaryRow{
			AssetID:          "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-uami-ctrl",
			AssetName:        "app-uami-ctrl",
			AssetKind:        "AppService",
			IdentityID:       "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app",
			IdentityName:     "ua-app",
			TargetResolution: "path-confirmed",
			RequiredEvidence: []string{"tokens-credentials", "workloads", "managed-identities", "permissions"},
		},
	}

	findings := validateComputeControlPayloadAgainstAzureContext(entry, "families compute-control (admin)", payload, context)
	if len(findings) == 0 {
		t.Fatal("expected a finding for the missing compute-control canary row")
	}
}

func TestValidateComputeControlPayloadAgainstAzureContextNormalizesTargetIdentityIDs(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "compute-control", Viewpoint: "admin"}
	payload := map[string]any{
		"paths": []any{
			map[string]any{
				"asset_id":          "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-uami-ctrl",
				"asset_name":        "app-uami-ctrl",
				"asset_kind":        "AppService",
				"source_command":    "tokens-credentials",
				"clue_type":         "managed-identity-token",
				"target_service":    "azure-control",
				"target_resolution": "path-confirmed",
				"target_count":      float64(1),
				"target_ids":        []any{"/subscriptions/test/resourcegroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"},
				"target_names":      []any{"ua-app"},
				"evidence_commands": []any{"tokens-credentials", "workloads", "managed-identities", "permissions"},
			},
		},
	}
	context := &liveComputeControlContextArtifact{
		Canary: &liveComputeControlCanaryRow{
			AssetID:          "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.Web/sites/app-uami-ctrl",
			AssetName:        "app-uami-ctrl",
			AssetKind:        "AppService",
			IdentityID:       "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app",
			IdentityName:     "ua-app",
			TargetResolution: "path-confirmed",
			RequiredEvidence: []string{"tokens-credentials", "workloads", "managed-identities", "permissions"},
		},
	}

	findings := validateComputeControlPayloadAgainstAzureContext(entry, "families compute-control (admin)", payload, context)
	if len(findings) != 0 {
		t.Fatalf("expected no findings after normalizing target identity ids, got %#v", findings)
	}
}
