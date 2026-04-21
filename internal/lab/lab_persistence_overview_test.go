package lab

import "testing"

func TestValidatePersistenceOverviewPayloadPassesForExpectedContract(t *testing.T) {
	surface := SurfaceSnapshot{
		Families: []string{"compute-control", "automation", "logic-apps"},
		FamilyGroupCommands: map[string]string{
			"compute-control": "chains",
			"automation":      "persistence",
			"logic-apps":      "persistence",
		},
		CommandTopLevelFields: map[string][]string{
			"persistence": {"metadata", "grouped_command_name", "command_state", "current_behavior", "planned_input_modes", "preferred_artifact_order", "selected_surface", "surfaces", "issues"},
		},
	}
	payload := map[string]any{
		"metadata":                 map[string]any{"command": "persistence"},
		"grouped_command_name":     "persistence",
		"command_state":            "implemented",
		"current_behavior":         "behavior",
		"planned_input_modes":      []any{"live"},
		"preferred_artifact_order": []any{"loot", "json"},
		"selected_surface":         nil,
		"surfaces": []any{
			map[string]any{
				"surface":           "automation",
				"state":             "implemented",
				"summary":           "summary",
				"operator_question": "question",
				"backing_commands":  []any{"automation", "permissions", "rbac"},
			},
			map[string]any{
				"surface":           "logic-apps",
				"state":             "implemented",
				"summary":           "summary",
				"operator_question": "question",
				"backing_commands":  []any{"logic-apps", "permissions", "rbac"},
			},
		},
		"issues": []any{},
	}

	findings := validatePersistenceOverviewPayload("commands persistence (overview)", payload, surface)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidatePersistenceOverviewPayloadFlagsSelectedSurfaceDrift(t *testing.T) {
	surface := SurfaceSnapshot{
		Families: []string{"automation"},
		FamilyGroupCommands: map[string]string{
			"automation": "persistence",
		},
		CommandTopLevelFields: map[string][]string{
			"persistence": {"metadata", "grouped_command_name", "command_state", "current_behavior", "planned_input_modes", "preferred_artifact_order", "selected_surface", "surfaces", "issues"},
		},
	}
	payload := map[string]any{
		"metadata":                 map[string]any{"command": "persistence"},
		"grouped_command_name":     "persistence",
		"command_state":            "implemented",
		"current_behavior":         "behavior",
		"planned_input_modes":      []any{"live"},
		"preferred_artifact_order": []any{"loot", "json"},
		"selected_surface":         "automation",
		"surfaces": []any{
			map[string]any{
				"surface":           "automation",
				"state":             "implemented",
				"summary":           "summary",
				"operator_question": "question",
				"backing_commands":  []any{"automation", "permissions", "rbac"},
			},
		},
		"issues": []any{},
	}

	findings := validatePersistenceOverviewPayload("commands persistence (overview)", payload, surface)
	if len(findings) == 0 {
		t.Fatal("expected a finding for unexpected selected_surface in the overview helper")
	}
}

func TestValidatePersistenceOverviewPayloadFlagsSurfaceSetDrift(t *testing.T) {
	surface := SurfaceSnapshot{
		Families: []string{"automation", "logic-apps"},
		FamilyGroupCommands: map[string]string{
			"automation": "persistence",
			"logic-apps": "persistence",
		},
		CommandTopLevelFields: map[string][]string{
			"persistence": {"metadata", "grouped_command_name", "command_state", "current_behavior", "planned_input_modes", "preferred_artifact_order", "selected_surface", "surfaces", "issues"},
		},
	}
	payload := map[string]any{
		"metadata":                 map[string]any{"command": "persistence"},
		"grouped_command_name":     "persistence",
		"command_state":            "implemented",
		"current_behavior":         "behavior",
		"planned_input_modes":      []any{"live"},
		"preferred_artifact_order": []any{"loot", "json"},
		"selected_surface":         nil,
		"surfaces": []any{
			map[string]any{
				"surface":           "automation",
				"state":             "implemented",
				"summary":           "summary",
				"operator_question": "question",
				"backing_commands":  []any{"automation", "permissions", "rbac"},
			},
		},
		"issues": []any{},
	}

	findings := validatePersistenceOverviewPayload("commands persistence (overview)", payload, surface)
	if len(findings) == 0 {
		t.Fatal("expected a finding for persistence surface inventory drift")
	}
}
