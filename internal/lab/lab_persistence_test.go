package lab

import (
	"slices"
	"testing"
)

func TestDeriveSurfaceIncludesPersistenceGroupedSurfaces(t *testing.T) {
	surface, err := DeriveSurface(hoAzureDir)
	if err != nil {
		t.Fatalf("derive surface: %v", err)
	}

	if !slices.Contains(surface.Families, "automation") {
		t.Fatalf("expected persistence automation surface in families: %#v", surface.Families)
	}
	if surface.FamilyGroupCommands["automation"] != "persistence" {
		t.Fatalf("expected automation grouped surface to use persistence, got %q", surface.FamilyGroupCommands["automation"])
	}
	if !slices.Contains(surface.Families, "logic-apps") {
		t.Fatalf("expected persistence logic-apps surface in families: %#v", surface.Families)
	}
	if surface.FamilyGroupCommands["logic-apps"] != "persistence" {
		t.Fatalf("expected logic-apps grouped surface to use persistence, got %q", surface.FamilyGroupCommands["logic-apps"])
	}
}

func TestGroupedFamilyTopLevelFieldsForPersistence(t *testing.T) {
	fields := groupedFamilyTopLevelFields("persistence")
	for _, required := range []string{"surface", "backing_commands", "issues"} {
		if !slices.Contains(fields, required) {
			t.Fatalf("expected grouped persistence fields to include %q: %#v", required, fields)
		}
	}
	for _, forbidden := range []string{"claim_boundary", "artifact_preference_order", "paths"} {
		if slices.Contains(fields, forbidden) {
			t.Fatalf("did not expect grouped persistence fields to include %q: %#v", forbidden, fields)
		}
	}
}

func TestTruthFirstBootstrapManifestTracksPersistenceFamilies(t *testing.T) {
	manifest, err := ScaffoldManifest(hoAzureDir, "excepted", "bootstrap_pending", "truth-first-bootstrap")
	if err != nil {
		t.Fatalf("scaffold manifest: %v", err)
	}

	if manifest.Surfaces.Families["automation"].Status != "covered" {
		t.Fatalf("expected persistence automation family to be covered, got %#v", manifest.Surfaces.Families["automation"])
	}
	if manifest.Surfaces.Families["logic-apps"].Status != "covered" {
		t.Fatalf("expected persistence logic-apps family to be covered, got %#v", manifest.Surfaces.Families["logic-apps"])
	}
}

func TestValidatePersistenceAutomationPayloadAgainstSourceTruthPassesForDerivedRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "automation", Viewpoint: "admin"}
	payload := map[string]any{
		"automation_accounts": []any{
			map[string]any{
				"id":                 "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops",
				"automation_account": "aa-ops",
				"resource_group":     "rg-ops",
				"location":           "centralus",
				"capability_steps": []any{
					map[string]any{"action": "create or modify account", "status": "yes"},
					map[string]any{"action": "add or edit runbook", "status": "yes"},
					map[string]any{"action": "upload or replace code", "status": "yes"},
					map[string]any{"action": "publish runbook", "status": "yes"},
					map[string]any{"action": "attach or reuse exec ctx", "status": "yes"},
					map[string]any{"action": "create schedule", "status": "yes"},
					map[string]any{"action": "link schedule to runbook", "status": "yes"},
					map[string]any{"action": "create webhook", "status": "yes"},
				},
				"current_identity_context": map[string]any{
					"kind":         "current-foothold",
					"principal_id": "user-1",
					"role_names":   []any{"Owner"},
				},
				"execution_context_options": []any{"managed identity"},
				"current_state": map[string]any{
					"runbook_count":             float64(1),
					"published_runbook_count":   float64(1),
					"published_runbook_names":   []any{"rb-proof"},
					"schedule_count":            float64(1),
					"job_schedule_count":        float64(1),
					"webhook_count":             float64(1),
					"hybrid_worker_group_count": float64(0),
					"credential_count":          float64(0),
					"certificate_count":         float64(0),
					"connection_count":          float64(0),
					"variable_count":            float64(0),
					"encrypted_variable_count":  float64(0),
					"primary_start_mode":        "webhook",
					"primary_runbook_name":      "rb-proof",
					"identity_type":             "SystemAssigned",
					"missing_target_mapping":    true,
					"strongest_visible_execution_context": map[string]any{
						"kind":         "automation-execution-context",
						"principal_id": "principal-automation",
						"role_names":   []any{},
					},
				},
			},
		},
	}
	automationPayload := map[string]any{
		"automation_accounts": []any{
			map[string]any{
				"id":                        "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops",
				"name":                      "aa-ops",
				"resource_group":            "rg-ops",
				"location":                  "centralus",
				"identity_type":             "SystemAssigned",
				"principal_id":              "principal-automation",
				"runbook_count":             float64(1),
				"published_runbook_count":   float64(1),
				"published_runbook_names":   []any{"rb-proof"},
				"schedule_count":            float64(1),
				"job_schedule_count":        float64(1),
				"webhook_count":             float64(1),
				"hybrid_worker_group_count": float64(0),
				"credential_count":          float64(0),
				"certificate_count":         float64(0),
				"connection_count":          float64(0),
				"variable_count":            float64(0),
				"encrypted_variable_count":  float64(0),
				"primary_start_mode":        "webhook",
				"primary_runbook_name":      "rb-proof",
				"missing_target_mapping":    true,
			},
		},
	}
	permissionsPayload := map[string]any{
		"permissions": []any{
			map[string]any{
				"principal_id":        "user-1",
				"is_current_identity": true,
				"high_impact_roles":   []any{"Owner"},
				"all_role_names":      []any{"Owner"},
			},
		},
	}
	rbacPayload := map[string]any{
		"role_assignments": []any{
			map[string]any{
				"principal_id": "user-1",
				"role_name":    "Owner",
				"scope_id":     "/subscriptions/sub-123",
			},
		},
	}

	findings := validatePersistenceAutomationPayloadAgainstSourceTruth(entry, "families persistence automation (admin)", payload, automationPayload, permissionsPayload, rbacPayload)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidatePersistenceAutomationPayloadAgainstSourceTruthFlagsMissingRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "automation", Viewpoint: "admin"}
	payload := map[string]any{"automation_accounts": []any{}}
	automationPayload := map[string]any{
		"automation_accounts": []any{
			map[string]any{
				"id":             "/subscriptions/sub-123/resourceGroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-ops",
				"name":           "aa-ops",
				"resource_group": "rg-ops",
			},
		},
	}

	findings := validatePersistenceAutomationPayloadAgainstSourceTruth(entry, "families persistence automation (admin)", payload, automationPayload, map[string]any{}, map[string]any{})
	if len(findings) == 0 {
		t.Fatal("expected a finding for missing persistence automation row")
	}
}

func TestValidatePersistenceLogicAppsPayloadAgainstSourceTruthPassesForDerivedRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "logic-apps", Viewpoint: "admin"}
	payload := map[string]any{
		"workflows": []any{
			map[string]any{
				"id":             "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-proof",
				"logic_app":      "la-proof",
				"resource_group": "rg-workload",
				"location":       "centralus",
				"capability_steps": []any{
					map[string]any{"action": "create or modify workflow", "status": "yes"},
					map[string]any{"action": "edit workflow definition", "status": "yes"},
					map[string]any{"action": "attach or reuse exec ctx", "status": "yes"},
					map[string]any{"action": "define or modify trigger", "status": "yes"},
					map[string]any{"action": "enable workflow", "status": "yes"},
					map[string]any{"action": "add or repurpose downstream actions", "status": "yes"},
				},
				"current_identity_context": map[string]any{
					"kind":         "current-foothold",
					"principal_id": "user-1",
					"role_names":   []any{"Owner"},
				},
				"execution_context_options": []any{"managed identity"},
				"current_state": map[string]any{
					"classification":                      "persistence-capable",
					"platform":                            "Consumption",
					"workflow_kind":                       "Stateful",
					"state":                               "Enabled",
					"recurrence_summary":                  "",
					"identity_type":                       "SystemAssigned",
					"trigger_types":                       []any{"request"},
					"externally_callable_request_trigger": true,
					"downstream_action_kinds":             []any{"external-http"},
					"strongest_visible_execution_context": map[string]any{
						"kind":          "logic-app-execution-context",
						"principal_id":  "workflow-principal",
						"identity_type": "SystemAssigned",
						"role_names":    []any{"Owner"},
						"scope_ids":     []any{"/subscriptions/sub-123"},
					},
				},
			},
		},
	}
	logicAppsPayload := map[string]any{
		"workflows": []any{
			map[string]any{
				"id":                                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-proof",
				"logic_app":                           "la-proof",
				"resource_group":                      "rg-workload",
				"location":                            "centralus",
				"classification":                      "persistence-capable",
				"platform":                            "Consumption",
				"workflow_kind":                       "Stateful",
				"state":                               "Enabled",
				"recurrence_summary":                  "",
				"identity_type":                       "SystemAssigned",
				"principal_id":                        "workflow-principal",
				"trigger_types":                       []any{"request"},
				"externally_callable_request_trigger": true,
				"downstream_action_kinds":             []any{"external-http"},
			},
		},
	}
	permissionsPayload := map[string]any{
		"permissions": []any{
			map[string]any{
				"principal_id":        "user-1",
				"is_current_identity": true,
				"high_impact_roles":   []any{"Owner"},
				"all_role_names":      []any{"Owner"},
				"scope_ids":           []any{"/subscriptions/sub-123"},
			},
			map[string]any{
				"principal_id":      "workflow-principal",
				"high_impact_roles": []any{"Owner"},
				"all_role_names":    []any{"Owner"},
				"scope_ids":         []any{"/subscriptions/sub-123"},
			},
		},
	}
	rbacPayload := map[string]any{
		"role_assignments": []any{
			map[string]any{
				"principal_id": "user-1",
				"role_name":    "Owner",
				"scope_id":     "/subscriptions/sub-123",
			},
		},
	}

	findings := validatePersistenceLogicAppsPayloadAgainstSourceTruth(entry, "families persistence logic-apps (admin)", payload, logicAppsPayload, permissionsPayload, rbacPayload)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidatePersistenceLogicAppsPayloadAgainstSourceTruthFlagsMissingRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "logic-apps", Viewpoint: "admin"}
	payload := map[string]any{"workflows": []any{}}
	logicAppsPayload := map[string]any{
		"workflows": []any{
			map[string]any{
				"id":             "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Logic/workflows/la-proof",
				"logic_app":      "la-proof",
				"resource_group": "rg-workload",
			},
		},
	}

	findings := validatePersistenceLogicAppsPayloadAgainstSourceTruth(entry, "families persistence logic-apps (admin)", payload, logicAppsPayload, map[string]any{}, map[string]any{})
	if len(findings) == 0 {
		t.Fatal("expected a finding for missing persistence logic-app row")
	}
}
