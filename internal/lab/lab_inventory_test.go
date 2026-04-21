package lab

import "testing"

func TestValidateInventoryPayloadAgainstAzureContextPassesForMatchingCounts(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "commands", SurfaceName: "inventory", Viewpoint: "admin"}
	payload := map[string]any{
		"metadata": map[string]any{
			"command":         "inventory",
			"tenant_id":       "tenant-123",
			"subscription_id": "sub-123",
		},
		"resource_count":       float64(3),
		"resource_group_count": float64(2),
		"subscription": map[string]any{
			"id":           "sub-123",
			"display_name": "Lab Subscription",
			"state":        "Enabled",
		},
		"top_resource_types": map[string]any{
			"Microsoft.Storage/storageAccounts": float64(2),
			"Microsoft.Web/sites":               float64(1),
		},
		"issues": []any{},
	}
	context := &liveInventoryContextArtifact{
		TenantID: "tenant-123",
		Subscription: inventoryTruth{
			ID:          "sub-123",
			DisplayName: "Lab Subscription",
			State:       "Enabled",
		},
		ResourceCount:      3,
		ResourceGroupCount: 2,
		TopResourceTypes: map[string]int{
			"Microsoft.Storage/storageAccounts": 2,
			"Microsoft.Web/sites":               1,
		},
	}

	findings := validateInventoryPayloadAgainstAzureContext(entry, "commands inventory (admin)", payload, context)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidateInventoryPayloadAgainstAzureContextFlagsResourceCountDrift(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "commands", SurfaceName: "inventory", Viewpoint: "admin"}
	payload := map[string]any{
		"metadata": map[string]any{
			"command":         "inventory",
			"tenant_id":       "tenant-123",
			"subscription_id": "sub-123",
		},
		"resource_count":       float64(2),
		"resource_group_count": float64(2),
		"subscription": map[string]any{
			"id":           "sub-123",
			"display_name": "Lab Subscription",
			"state":        "Enabled",
		},
		"top_resource_types": map[string]any{
			"Microsoft.Storage/storageAccounts": float64(2),
			"Microsoft.Web/sites":               float64(1),
		},
		"issues": []any{},
	}
	context := &liveInventoryContextArtifact{
		TenantID: "tenant-123",
		Subscription: inventoryTruth{
			ID:          "sub-123",
			DisplayName: "Lab Subscription",
			State:       "Enabled",
		},
		ResourceCount:      3,
		ResourceGroupCount: 2,
		TopResourceTypes: map[string]int{
			"Microsoft.Storage/storageAccounts": 2,
			"Microsoft.Web/sites":               1,
		},
	}

	findings := validateInventoryPayloadAgainstAzureContext(entry, "commands inventory (admin)", payload, context)
	if len(findings) == 0 {
		t.Fatal("expected a finding for resource_count drift")
	}
}

func TestValidateInventoryPayloadAgainstAzureContextFlagsMissingContext(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "commands", SurfaceName: "inventory", Viewpoint: "admin"}
	findings := validateInventoryPayloadAgainstAzureContext(entry, "commands inventory (admin)", map[string]any{}, nil)
	if len(findings) == 0 {
		t.Fatal("expected a finding for missing live inventory context")
	}
}
