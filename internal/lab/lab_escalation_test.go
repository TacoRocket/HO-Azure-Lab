package lab

import "testing"

func TestValidateEscalationPathPayloadAgainstSourceTruthPassesForDirectAndTrustRows(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "escalation-path", Viewpoint: "admin"}
	payload := map[string]any{
		"paths": []any{
			map[string]any{
				"asset_id":          "user-1",
				"source_command":    "permissions",
				"clue_type":         "direct-role-abuse",
				"target_service":    "azure-control",
				"target_resolution": "path-confirmed",
				"target_ids":        []any{"/subscriptions/sub-123"},
			},
			map[string]any{
				"asset_id":          "user-1",
				"source_command":    "role-trusts",
				"clue_type":         "service-principal-owner",
				"target_service":    "identity-trust",
				"target_resolution": "path-confirmed",
				"target_ids":        []any{"sp-1"},
			},
		},
	}
	permissionsPayload := map[string]any{
		"permissions": []any{
			map[string]any{
				"principal_id":        "user-1",
				"is_current_identity": true,
				"privileged":          true,
				"scope_ids":           []any{"/subscriptions/sub-123"},
			},
			map[string]any{
				"principal_id":        "sp-1",
				"is_current_identity": false,
				"privileged":          true,
			},
		},
	}
	roleTrustsPayload := map[string]any{
		"trusts": []any{
			map[string]any{
				"trust_type":       "service-principal-owner",
				"source_object_id": "user-1",
				"target_object_id": "sp-1",
			},
		},
	}

	findings := validateEscalationPathPayloadAgainstSourceTruth(entry, "families escalation-path (admin)", payload, permissionsPayload, roleTrustsPayload)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestValidateEscalationPathPayloadAgainstSourceTruthFlagsMissingDirectRow(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "escalation-path", Viewpoint: "admin"}
	payload := map[string]any{"paths": []any{}}
	permissionsPayload := map[string]any{
		"permissions": []any{
			map[string]any{
				"principal_id":        "user-1",
				"is_current_identity": true,
				"privileged":          true,
			},
		},
	}
	roleTrustsPayload := map[string]any{"trusts": []any{}}

	findings := validateEscalationPathPayloadAgainstSourceTruth(entry, "families escalation-path (admin)", payload, permissionsPayload, roleTrustsPayload)
	if len(findings) == 0 {
		t.Fatal("expected a finding for missing direct-control escalation row")
	}
}

func TestValidateEscalationPathPayloadAgainstSourceTruthFlagsUnexpectedRowsWithoutFoothold(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "escalation-path", Viewpoint: "dev"}
	payload := map[string]any{
		"paths": []any{
			map[string]any{
				"asset_id":       "user-2",
				"source_command": "permissions",
			},
		},
	}
	permissionsPayload := map[string]any{
		"permissions": []any{
			map[string]any{
				"principal_id":        "user-2",
				"is_current_identity": true,
				"privileged":          false,
			},
		},
	}
	roleTrustsPayload := map[string]any{"trusts": []any{}}

	findings := validateEscalationPathPayloadAgainstSourceTruth(entry, "families escalation-path (dev)", payload, permissionsPayload, roleTrustsPayload)
	if len(findings) == 0 {
		t.Fatal("expected a finding for unexpected escalation rows without a defended foothold")
	}
}

func TestValidateEscalationPathPayloadAgainstSourceTruthAllowsSuppressedNonNetNewTrustRows(t *testing.T) {
	entry := CommandLogEntry{SurfaceKind: "families", SurfaceName: "escalation-path", Viewpoint: "admin"}
	payload := map[string]any{
		"paths": []any{
			map[string]any{
				"asset_id":          "user-1",
				"source_command":    "permissions",
				"clue_type":         "direct-role-abuse",
				"target_service":    "azure-control",
				"target_resolution": "path-confirmed",
				"target_ids":        []any{"/subscriptions/sub-123"},
			},
		},
	}
	permissionsPayload := map[string]any{
		"permissions": []any{
			map[string]any{
				"principal_id":        "user-1",
				"is_current_identity": true,
				"privileged":          true,
				"high_impact_roles":   []any{"Owner"},
				"scope_ids":           []any{"/subscriptions/sub-123"},
			},
			map[string]any{
				"principal_id":        "sp-1",
				"is_current_identity": false,
				"privileged":          true,
				"high_impact_roles":   []any{"Contributor"},
				"scope_ids":           []any{"/subscriptions/sub-123/resourceGroups/rg-workload"},
			},
		},
	}
	roleTrustsPayload := map[string]any{
		"trusts": []any{
			map[string]any{
				"trust_type":       "service-principal-owner",
				"source_object_id": "user-1",
				"target_object_id": "sp-1",
			},
		},
	}

	findings := validateEscalationPathPayloadAgainstSourceTruth(entry, "families escalation-path (admin)", payload, permissionsPayload, roleTrustsPayload)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when trust rows are correctly suppressed as non-net-new, got %#v", findings)
	}
}
