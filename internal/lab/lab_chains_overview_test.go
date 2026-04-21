package lab

import "testing"

func TestValidateChainsOverviewPayloadPassesForExpectedContract(t *testing.T) {
	surface := SurfaceSnapshot{
		Families: []string{"compute-control", "credential-path"},
		FamilyGroupCommands: map[string]string{
			"compute-control": "chains",
			"credential-path": "chains",
		},
		CommandTopLevelFields: map[string][]string{
			"chains": {"metadata", "grouped_command_name", "selected_family", "families", "issues"},
		},
	}
	payload := map[string]any{
		"metadata":             map[string]any{"command": "chains"},
		"grouped_command_name": "chains",
		"selected_family":      nil,
		"families": []any{
			map[string]any{
				"family":                "compute-control",
				"state":                 "implemented",
				"meaning":               "meaning",
				"summary":               "summary",
				"allowed_claim":         "allowed",
				"current_gap":           "gap",
				"best_current_examples": []any{"a"},
				"source_commands":       []any{map[string]any{"command": "tokens-credentials", "minimum_fields": []any{"asset_id"}, "rationale": "why"}},
			},
			map[string]any{
				"family":                "credential-path",
				"state":                 "implemented",
				"meaning":               "meaning",
				"summary":               "summary",
				"allowed_claim":         "allowed",
				"current_gap":           "gap",
				"best_current_examples": []any{"b"},
				"source_commands":       []any{map[string]any{"command": "env-vars", "minimum_fields": []any{"asset_id"}, "rationale": "why"}},
			},
		},
		"issues": []any{},
	}

	findings := validateChainsOverviewPayload("commands chains (overview)", payload, surface)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidateChainsOverviewPayloadFlagsSelectedFamilyDrift(t *testing.T) {
	surface := SurfaceSnapshot{
		Families: []string{"compute-control"},
		FamilyGroupCommands: map[string]string{
			"compute-control": "chains",
		},
		CommandTopLevelFields: map[string][]string{
			"chains": {"metadata", "grouped_command_name", "selected_family", "families", "issues"},
		},
	}
	payload := map[string]any{
		"metadata":             map[string]any{"command": "chains"},
		"grouped_command_name": "chains",
		"selected_family":      "compute-control",
		"families": []any{
			map[string]any{
				"family":                "compute-control",
				"state":                 "implemented",
				"meaning":               "meaning",
				"summary":               "summary",
				"allowed_claim":         "allowed",
				"current_gap":           "gap",
				"best_current_examples": []any{"a"},
				"source_commands":       []any{map[string]any{"command": "tokens-credentials", "minimum_fields": []any{"asset_id"}, "rationale": "why"}},
			},
		},
		"issues": []any{},
	}

	findings := validateChainsOverviewPayload("commands chains (overview)", payload, surface)
	if len(findings) == 0 {
		t.Fatal("expected a finding for unexpected selected_family in the overview helper")
	}
}

func TestValidateChainsOverviewPayloadFlagsFamilySetDrift(t *testing.T) {
	surface := SurfaceSnapshot{
		Families: []string{"compute-control", "credential-path"},
		FamilyGroupCommands: map[string]string{
			"compute-control": "chains",
			"credential-path": "chains",
		},
		CommandTopLevelFields: map[string][]string{
			"chains": {"metadata", "grouped_command_name", "selected_family", "families", "issues"},
		},
	}
	payload := map[string]any{
		"metadata":             map[string]any{"command": "chains"},
		"grouped_command_name": "chains",
		"selected_family":      nil,
		"families": []any{
			map[string]any{
				"family":                "compute-control",
				"state":                 "implemented",
				"meaning":               "meaning",
				"summary":               "summary",
				"allowed_claim":         "allowed",
				"current_gap":           "gap",
				"best_current_examples": []any{"a"},
				"source_commands":       []any{map[string]any{"command": "tokens-credentials", "minimum_fields": []any{"asset_id"}, "rationale": "why"}},
			},
		},
		"issues": []any{},
	}

	findings := validateChainsOverviewPayload("commands chains (overview)", payload, surface)
	if len(findings) == 0 {
		t.Fatal("expected a finding for family inventory drift")
	}
}
