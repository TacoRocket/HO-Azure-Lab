package lab

import (
	"fmt"
	"slices"
	"strings"
)

func persistenceAutomationRows(payload map[string]any) []map[string]any {
	rows, _ := payload["automation_accounts"].([]any)
	result := []map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, rowMap)
	}
	return result
}

func currentPermissionRow(payload map[string]any) map[string]any {
	rows, _ := payload["permissions"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		isCurrent, _ := rowMap["is_current_identity"].(bool)
		if isCurrent {
			return rowMap
		}
	}
	return nil
}

func rbacAssignmentsForPrincipal(payload map[string]any, principalID string) []map[string]any {
	rows, _ := payload["role_assignments"].([]any)
	result := []map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowPrincipalID, _ := rowMap["principal_id"].(string)
		if strings.TrimSpace(rowPrincipalID) != strings.TrimSpace(principalID) {
			continue
		}
		result = append(result, rowMap)
	}
	return result
}

func persistenceControlRank(scopeID, resourceID string) (int, bool) {
	scopeID = strings.TrimSpace(scopeID)
	resourceID = strings.TrimSpace(resourceID)
	if scopeID == "" || resourceID == "" {
		return 0, false
	}
	scopeLower := strings.ToLower(strings.TrimRight(scopeID, "/"))
	resourceLower := strings.ToLower(strings.TrimRight(resourceID, "/"))
	if scopeLower == resourceLower {
		return 0, true
	}
	if !strings.HasPrefix(resourceLower, scopeLower+"/") {
		return 0, false
	}
	if strings.Contains(scopeLower, "/resourcegroups/") {
		return 1, true
	}
	if strings.Contains(scopeLower, "/subscriptions/") {
		return 2, true
	}
	return 3, true
}

func persistenceAutomationControlFromPayload(resourceID string, assignments []map[string]any) (string, string, bool) {
	bestRank := 99
	bestRole := ""
	bestScopeID := ""
	for _, assignment := range assignments {
		roleName, _ := assignment["role_name"].(string)
		roleLower := strings.ToLower(strings.TrimSpace(roleName))
		if roleLower != "owner" && roleLower != "contributor" && roleLower != "automation contributor" {
			continue
		}
		scopeID, _ := assignment["scope_id"].(string)
		rank, ok := persistenceControlRank(scopeID, resourceID)
		if !ok || rank >= bestRank {
			continue
		}
		bestRank = rank
		bestRole = roleName
		bestScopeID = scopeID
	}
	return bestRole, bestScopeID, bestRank != 99
}

func persistenceAutomationExecutionOptionsFromSource(row map[string]any) []string {
	options := []string{}
	identityType, _ := row["identity_type"].(string)
	if strings.TrimSpace(identityType) != "" {
		options = append(options, "managed identity")
	}
	if count := rowIntPtr(row, "credential_count"); count != nil && *count > 0 {
		options = append(options, "stored credentials")
	}
	if count := rowIntPtr(row, "connection_count"); count != nil && *count > 0 {
		options = append(options, "connections")
	}
	if count := rowIntPtr(row, "certificate_count"); count != nil && *count > 0 {
		options = append(options, "certificates")
	}
	if count := rowIntPtr(row, "variable_count"); count != nil && *count > 0 {
		options = append(options, "variables")
	}
	slices.Sort(options)
	return slices.Compact(options)
}

func persistenceExpectedCapabilityStatus(action, roleName string, controlOK bool) string {
	if !controlOK {
		return "not proven"
	}
	roleLower := strings.ToLower(strings.TrimSpace(roleName))
	if roleLower == "automation contributor" &&
		(action == "create or modify account" || action == "attach or reuse exec ctx") {
		return "not proven"
	}
	return "yes"
}

func persistenceRoleLabel(roleName string) string {
	parts := strings.SplitN(strings.TrimSpace(roleName), " at ", 2)
	return strings.TrimSpace(parts[0])
}

func validatePersistenceAutomationPayloadAgainstSourceTruth(
	entry CommandLogEntry,
	label string,
	payload map[string]any,
	automationPayload map[string]any,
	permissionsPayload map[string]any,
	rbacPayload map[string]any,
) []Finding {
	if entry.SurfaceKind != "families" || entry.SurfaceName != "automation" {
		return nil
	}

	sourceRows := persistenceAutomationRows(automationPayload)
	groupedRows := persistenceAutomationRows(payload)
	findings := []Finding{}

	if len(groupedRows) != len(sourceRows) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d persistence automation rows, but the sibling automation payload shows %d visible automation account rows", label, len(groupedRows), len(sourceRows)),
			"persistence automation row admission",
			"persistence automation should preserve the same visible automation account inventory the sibling automation command already surfaced for this viewpoint",
		))
	}

	currentPermission := currentPermissionRow(permissionsPayload)
	currentPrincipalID, _ := currentPermission["principal_id"].(string)
	currentAssignments := rbacAssignmentsForPrincipal(rbacPayload, currentPrincipalID)
	permissionsByPrincipal := permissionRowsByPrincipalID(permissionsPayload)

	for _, sourceRow := range sourceRows {
		sourceID, _ := sourceRow["id"].(string)
		groupedRow := findAutomationRowByID(payload, sourceID)
		if groupedRow == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-account-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not preserve a persistence automation row for source automation account %q", label, sourceID),
				"persistence automation row admission",
				"persistence automation should preserve visible automation account rows from the sibling automation command when they are still in scope for this viewpoint",
			))
			continue
		}

		for key, expected := range map[string]string{
			"automation_account": func() string {
				name, _ := sourceRow["name"].(string)
				return name
			}(),
			"resource_group": func() string {
				resourceGroup, _ := sourceRow["resource_group"].(string)
				return resourceGroup
			}(),
			"location": func() string {
				location, _ := sourceRow["location"].(string)
				return location
			}(),
		} {
			observed, _ := groupedRow[key].(string)
			if strings.TrimSpace(observed) != strings.TrimSpace(expected) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s surfaced persistence automation row %q with %s %q, but the sibling automation payload reports %q", label, sourceID, key, observed, expected),
					"persistence automation source-field reuse",
					"persistence automation should preserve the visible automation account identity, naming, and placement fields from the sibling automation payload",
				))
			}
		}

		expectedOptions := persistenceAutomationExecutionOptionsFromSource(sourceRow)
		observedOptions := rowStringList(groupedRow, "execution_context_options")
		slices.Sort(observedOptions)
		observedOptions = slices.Compact(observedOptions)
		if !slices.Equal(observedOptions, expectedOptions) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-execution-options-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence automation row %q with execution_context_options %v, but the sibling automation payload supports %v", label, sourceID, observedOptions, expectedOptions),
				"persistence automation execution-context derivation",
				"persistence automation should derive execution context options directly from the sibling automation account identity and asset counts",
			))
		}

		currentState, _ := groupedRow["current_state"].(map[string]any)
		if currentState == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-current-state", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence automation row %q without current_state", label, sourceID),
				"persistence automation grouped row rendering",
				"persistence automation rows should preserve the grouped current_state object that explains the visible execution shape",
			))
			continue
		}

		for _, field := range []string{
			"runbook_count",
			"published_runbook_count",
			"schedule_count",
			"job_schedule_count",
			"webhook_count",
			"hybrid_worker_group_count",
			"credential_count",
			"certificate_count",
			"connection_count",
			"variable_count",
			"encrypted_variable_count",
		} {
			expected := rowIntPtr(sourceRow, field)
			observed := rowIntPtr(currentState, field)
			if (expected == nil) != (observed == nil) || (expected != nil && observed != nil && *expected != *observed) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s surfaced persistence automation row %q with %s %v, but the sibling automation payload reports %v", label, sourceID, field, observed, expected),
					"persistence automation current_state reuse",
					"persistence automation should preserve the visible automation execution counts from the sibling automation payload",
				))
			}
		}

		for _, field := range []string{"primary_start_mode", "primary_runbook_name", "identity_type"} {
			expected, _ := sourceRow[field].(string)
			observed, _ := currentState[field].(string)
			if strings.TrimSpace(observed) != strings.TrimSpace(expected) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s surfaced persistence automation row %q with %s %q, but the sibling automation payload reports %q", label, sourceID, field, observed, expected),
					"persistence automation current_state reuse",
					"persistence automation should preserve the visible automation start-mode and identity fields from the sibling automation payload",
				))
			}
		}

		expectedPublishedNames := rowStringList(sourceRow, "published_runbook_names")
		observedPublishedNames := rowStringList(currentState, "published_runbook_names")
		if !slices.Equal(observedPublishedNames, expectedPublishedNames) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-published-runbook-names-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence automation row %q with published_runbook_names %v, but the sibling automation payload reports %v", label, sourceID, observedPublishedNames, expectedPublishedNames),
				"persistence automation current_state reuse",
				"persistence automation should preserve the visible published runbook names from the sibling automation payload",
			))
		}

		expectedMissingTargetMapping := rowBoolPtr(sourceRow, "missing_target_mapping")
		observedMissingTargetMapping := rowBoolPtr(currentState, "missing_target_mapping")
		if (expectedMissingTargetMapping == nil) != (observedMissingTargetMapping == nil) ||
			(expectedMissingTargetMapping != nil && observedMissingTargetMapping != nil && *expectedMissingTargetMapping != *observedMissingTargetMapping) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-target-mapping-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence automation row %q with missing_target_mapping %v, but the sibling automation payload reports %v", label, sourceID, observedMissingTargetMapping, expectedMissingTargetMapping),
				"persistence automation current_state reuse",
				"persistence automation should preserve whether the sibling automation payload still lacks an exact downstream target mapping",
			))
		}

		roleName, _, controlOK := persistenceAutomationControlFromPayload(sourceID, currentAssignments)
		currentContext, _ := groupedRow["current_identity_context"].(map[string]any)
		if currentPermission == nil && !controlOK {
			if currentContext != nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-current-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced persistence automation row %q with current_identity_context even though the sibling permissions/rbac payloads do not defend one", label, sourceID),
					"persistence automation current identity derivation",
					"persistence automation should only surface a current_identity_context when the sibling permissions or rbac payloads defend that current foothold story",
				))
			}
		} else {
			if currentContext == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-current-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s did not surface current_identity_context for persistence automation row %q even though the sibling permissions/rbac payloads defend one", label, sourceID),
					"persistence automation current identity derivation",
					"persistence automation should preserve the defended current identity context for visible automation accounts",
				))
			} else {
				observedKind, _ := currentContext["kind"].(string)
				if observedKind != "current-foothold" {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-current-context-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence automation row %q with current_identity_context.kind %q", label, sourceID, observedKind),
						"persistence automation current identity derivation",
						"persistence automation should mark the current identity context as current-foothold when it is reusing the current permissions/rbac story",
					))
				}
				observedPrincipalID, _ := currentContext["principal_id"].(string)
				if strings.TrimSpace(currentPrincipalID) != "" && observedPrincipalID != currentPrincipalID {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-current-context-principal-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence automation row %q with current_identity_context.principal_id %q, but the sibling permissions payload reports %q", label, sourceID, observedPrincipalID, currentPrincipalID),
						"persistence automation current identity derivation",
						"persistence automation should preserve the same current principal identity the sibling permissions payload already marks as active",
					))
				}
				expectedRoleNames := []string{}
				if controlOK && strings.TrimSpace(roleName) != "" {
					expectedRoleNames = []string{persistenceRoleLabel(roleName)}
				}
				if len(expectedRoleNames) == 0 && currentPermission != nil {
					expectedRoleNames = payloadStringSliceValues(currentPermission, "high_impact_roles")
					if len(expectedRoleNames) == 0 {
						expectedRoleNames = payloadStringSliceValues(currentPermission, "all_role_names")
					}
				}
				observedRoleNames := rowStringList(currentContext, "role_names")
				if len(expectedRoleNames) > 0 && !slices.Equal(observedRoleNames, expectedRoleNames) {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-current-context-roles-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence automation row %q with current_identity_context.role_names %v, but the sibling permissions/rbac payloads defend %v", label, sourceID, observedRoleNames, expectedRoleNames),
						"persistence automation current identity derivation",
						"persistence automation should keep current identity role names aligned with the controlling rbac scope when it is visible, or the current permissions row when it is not",
					))
				}
			}
		}

		observedCapabilityStatuses := map[string]string{}
		capabilitySteps, _ := groupedRow["capability_steps"].([]any)
		for _, step := range capabilitySteps {
			stepMap, ok := step.(map[string]any)
			if !ok {
				continue
			}
			action, _ := stepMap["action"].(string)
			status, _ := stepMap["status"].(string)
			observedCapabilityStatuses[action] = status
		}
		for _, action := range []string{
			"create or modify account",
			"add or edit runbook",
			"upload or replace code",
			"publish runbook",
			"attach or reuse exec ctx",
			"create schedule",
			"link schedule to runbook",
			"create webhook",
		} {
			expected := persistenceExpectedCapabilityStatus(action, roleName, controlOK)
			observed, ok := observedCapabilityStatuses[action]
			if !ok || observed != expected {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-capability-step-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.ReplaceAll(action, " ", "-"), "/", "-")),
					fmt.Sprintf("%s surfaced persistence automation row %q with capability step %q status %q, but the sibling permissions/rbac payloads defend %q", label, sourceID, action, observed, expected),
					"persistence automation capability-step derivation",
					"persistence automation capability step status should stay aligned with whether the current identity really has defended automation control at the relevant scope",
				))
			}
		}

		strongestContext, _ := currentState["strongest_visible_execution_context"].(map[string]any)
		sourcePrincipalID, _ := sourceRow["principal_id"].(string)
		if strings.TrimSpace(sourcePrincipalID) == "" {
			if strongestContext != nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-execution-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced persistence automation row %q with strongest_visible_execution_context even though the sibling automation payload does not expose an execution principal", label, sourceID),
					"persistence automation execution-context derivation",
					"persistence automation should only surface strongest execution context when the sibling automation payload exposes an execution identity to reason about",
				))
			}
		} else {
			if strongestContext == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-execution-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s did not surface strongest_visible_execution_context for persistence automation row %q even though the sibling automation payload exposes an execution principal", label, sourceID),
					"persistence automation execution-context derivation",
					"persistence automation should preserve the visible execution identity context when the sibling automation payload exposes one",
				))
			} else {
				observedKind, _ := strongestContext["kind"].(string)
				if observedKind != "automation-execution-context" {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-execution-context-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence automation row %q with strongest_visible_execution_context.kind %q", label, sourceID, observedKind),
						"persistence automation execution-context derivation",
						"persistence automation should mark the execution identity as automation-execution-context when it is reusing the sibling automation identity story",
					))
				}
				observedPrincipalID, _ := strongestContext["principal_id"].(string)
				if observedPrincipalID != sourcePrincipalID {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-execution-context-principal-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence automation row %q with strongest_visible_execution_context.principal_id %q, but the sibling automation payload reports %q", label, sourceID, observedPrincipalID, sourcePrincipalID),
						"persistence automation execution-context derivation",
						"persistence automation should preserve the same execution principal the sibling automation payload already exposed",
					))
				}
				sourcePermission := permissionsByPrincipal[sourcePrincipalID]
				observedRoleNames := rowStringList(strongestContext, "role_names")
				if sourcePermission == nil {
					if len(observedRoleNames) != 0 {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-execution-context-roles-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							fmt.Sprintf("%s surfaced persistence automation row %q with strongest_visible_execution_context.role_names %v even though the sibling permissions payload shows no matching execution-principal permission row", label, sourceID, observedRoleNames),
							"persistence automation execution-context derivation",
							"persistence automation should leave execution-context role_names empty when the sibling permissions payload cannot match the automation identity to Azure role context",
						))
					}
				} else {
					expectedRoleNames := payloadStringSliceValues(sourcePermission, "high_impact_roles")
					if len(expectedRoleNames) == 0 {
						expectedRoleNames = payloadStringSliceValues(sourcePermission, "all_role_names")
					}
					if !slices.Equal(observedRoleNames, expectedRoleNames) {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-execution-context-roles-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							fmt.Sprintf("%s surfaced persistence automation row %q with strongest_visible_execution_context.role_names %v, but the sibling permissions payload reports %v", label, sourceID, observedRoleNames, expectedRoleNames),
							"persistence automation execution-context derivation",
							"persistence automation should preserve the visible Azure role context for the execution identity when the sibling permissions payload can match it",
						))
					}
				}
			}
		}
	}

	return findings
}

func persistenceLogicAppRows(payload map[string]any) []map[string]any {
	rows, _ := payload["workflows"].([]any)
	result := []map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, rowMap)
	}
	return result
}

func persistenceLogicAppExecutionOptionsFromSource(row map[string]any) []string {
	options := []string{}
	identityType, _ := row["identity_type"].(string)
	if strings.TrimSpace(identityType) != "" {
		options = append(options, "managed identity")
	}
	for _, kind := range rowStringList(row, "downstream_action_kinds") {
		if strings.EqualFold(strings.TrimSpace(kind), "connector") {
			options = append(options, "connector-backed actions")
			break
		}
	}
	slices.Sort(options)
	return slices.Compact(options)
}

func persistenceExpectedLogicAppCapabilityStatus(controlOK bool) string {
	if !controlOK {
		return "not proven"
	}
	return "yes"
}

func validatePersistenceLogicAppsPayloadAgainstSourceTruth(
	entry CommandLogEntry,
	label string,
	payload map[string]any,
	logicAppsPayload map[string]any,
	permissionsPayload map[string]any,
	rbacPayload map[string]any,
) []Finding {
	if entry.SurfaceKind != "families" || entry.SurfaceName != "logic-apps" {
		return nil
	}

	sourceRows := persistenceLogicAppRows(logicAppsPayload)
	groupedRows := persistenceLogicAppRows(payload)
	findings := []Finding{}

	if len(groupedRows) != len(sourceRows) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d persistence logic-app rows, but the sibling logic-apps payload shows %d visible workflows", label, len(groupedRows), len(sourceRows)),
			"persistence logic-apps row admission",
			"persistence logic-apps should preserve the same visible workflow inventory the sibling logic-apps command already surfaced for this viewpoint",
		))
	}

	currentPermission := currentPermissionRow(permissionsPayload)
	currentPrincipalID, _ := currentPermission["principal_id"].(string)
	currentAssignments := rbacAssignmentsForPrincipal(rbacPayload, currentPrincipalID)
	permissionsByPrincipal := permissionRowsByPrincipalID(permissionsPayload)

	for _, sourceRow := range sourceRows {
		sourceID, _ := sourceRow["id"].(string)
		groupedRow := findLogicAppRowByID(payload, sourceID)
		if groupedRow == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-workflow-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not preserve a persistence logic-app row for source workflow %q", label, sourceID),
				"persistence logic-apps row admission",
				"persistence logic-apps should preserve visible Logic App workflow rows from the sibling logic-apps command when they are still in scope for this viewpoint",
			))
			continue
		}

		for key, expected := range map[string]string{
			"logic_app": func() string {
				name, _ := sourceRow["logic_app"].(string)
				return name
			}(),
			"resource_group": func() string {
				resourceGroup, _ := sourceRow["resource_group"].(string)
				return resourceGroup
			}(),
			"location": func() string {
				location, _ := sourceRow["location"].(string)
				return location
			}(),
		} {
			observed, _ := groupedRow[key].(string)
			if strings.TrimSpace(observed) != strings.TrimSpace(expected) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s surfaced persistence logic-app row %q with %s %q, but the sibling logic-apps payload reports %q", label, sourceID, key, observed, expected),
					"persistence logic-apps source-field reuse",
					"persistence logic-apps should preserve the visible workflow identity, naming, and placement fields from the sibling logic-apps payload",
				))
			}
		}

		expectedOptions := persistenceLogicAppExecutionOptionsFromSource(sourceRow)
		observedOptions := rowStringList(groupedRow, "execution_context_options")
		slices.Sort(observedOptions)
		observedOptions = slices.Compact(observedOptions)
		if !slices.Equal(observedOptions, expectedOptions) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-execution-options-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence logic-app row %q with execution_context_options %v, but the sibling logic-apps payload supports %v", label, sourceID, observedOptions, expectedOptions),
				"persistence logic-apps execution-context derivation",
				"persistence logic-apps should derive execution context options directly from the sibling workflow identity and visible downstream action kinds",
			))
		}

		currentState, _ := groupedRow["current_state"].(map[string]any)
		if currentState == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-current-state", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence logic-app row %q without current_state", label, sourceID),
				"persistence logic-apps grouped row rendering",
				"persistence logic-app rows should preserve the grouped current_state object that explains the visible durable trigger and action posture",
			))
			continue
		}

		for _, field := range []string{"classification", "platform", "workflow_kind", "state", "recurrence_summary", "identity_type"} {
			expected, _ := sourceRow[field].(string)
			observed, _ := currentState[field].(string)
			if strings.TrimSpace(observed) != strings.TrimSpace(expected) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s surfaced persistence logic-app row %q with %s %q, but the sibling logic-apps payload reports %q", label, sourceID, field, observed, expected),
					"persistence logic-apps current_state reuse",
					"persistence logic-apps should preserve the visible workflow classification, trigger posture, and identity fields from the sibling logic-apps payload",
				))
			}
		}

		expectedTriggerTypes := rowStringList(sourceRow, "trigger_types")
		observedTriggerTypes := rowStringList(currentState, "trigger_types")
		if !slices.Equal(observedTriggerTypes, expectedTriggerTypes) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-trigger-types-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence logic-app row %q with trigger_types %v, but the sibling logic-apps payload reports %v", label, sourceID, observedTriggerTypes, expectedTriggerTypes),
				"persistence logic-apps current_state reuse",
				"persistence logic-apps should preserve the visible Logic App trigger types from the sibling logic-apps payload",
			))
		}

		expectedActionKinds := rowStringList(sourceRow, "downstream_action_kinds")
		observedActionKinds := rowStringList(currentState, "downstream_action_kinds")
		if !slices.Equal(observedActionKinds, expectedActionKinds) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-downstream-action-kinds-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence logic-app row %q with downstream_action_kinds %v, but the sibling logic-apps payload reports %v", label, sourceID, observedActionKinds, expectedActionKinds),
				"persistence logic-apps current_state reuse",
				"persistence logic-apps should preserve the visible Logic App downstream action kinds from the sibling logic-apps payload",
			))
		}

		expectedExternalRequest := rowBoolPtr(sourceRow, "externally_callable_request_trigger")
		observedExternalRequest := rowBoolPtr(currentState, "externally_callable_request_trigger")
		if (expectedExternalRequest == nil) != (observedExternalRequest == nil) ||
			(expectedExternalRequest != nil && observedExternalRequest != nil && *expectedExternalRequest != *observedExternalRequest) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-external-request-trigger-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced persistence logic-app row %q with externally_callable_request_trigger %v, but the sibling logic-apps payload reports %v", label, sourceID, observedExternalRequest, expectedExternalRequest),
				"persistence logic-apps current_state reuse",
				"persistence logic-apps should preserve whether the sibling logic-apps payload already shows an externally callable request trigger",
			))
		}

		roleName, _, controlOK := persistenceAutomationControlFromPayload(sourceID, currentAssignments)
		currentContext, _ := groupedRow["current_identity_context"].(map[string]any)
		if currentPermission == nil && !controlOK {
			if currentContext != nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-current-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced persistence logic-app row %q with current_identity_context even though the sibling permissions/rbac payloads do not defend one", label, sourceID),
					"persistence logic-apps current identity derivation",
					"persistence logic-apps should only surface a current_identity_context when the sibling permissions or rbac payloads defend that current foothold story",
				))
			}
		} else {
			if currentContext == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-current-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s did not surface current_identity_context for persistence logic-app row %q even though the sibling permissions/rbac payloads defend one", label, sourceID),
					"persistence logic-apps current identity derivation",
					"persistence logic-apps should preserve the defended current identity context for visible Logic App workflows",
				))
			} else {
				observedKind, _ := currentContext["kind"].(string)
				if observedKind != "current-foothold" {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-current-context-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence logic-app row %q with current_identity_context.kind %q", label, sourceID, observedKind),
						"persistence logic-apps current identity derivation",
						"persistence logic-apps should mark the current identity context as current-foothold when it is reusing the current permissions/rbac story",
					))
				}
				observedPrincipalID, _ := currentContext["principal_id"].(string)
				if strings.TrimSpace(currentPrincipalID) != "" && observedPrincipalID != currentPrincipalID {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-current-context-principal-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence logic-app row %q with current_identity_context.principal_id %q, but the sibling permissions payload reports %q", label, sourceID, observedPrincipalID, currentPrincipalID),
						"persistence logic-apps current identity derivation",
						"persistence logic-apps should preserve the same current principal identity the sibling permissions payload already marks as active",
					))
				}
				expectedRoleNames := []string{}
				if controlOK && strings.TrimSpace(roleName) != "" {
					expectedRoleNames = []string{persistenceRoleLabel(roleName)}
				}
				if len(expectedRoleNames) == 0 && currentPermission != nil {
					expectedRoleNames = payloadStringSliceValues(currentPermission, "high_impact_roles")
					if len(expectedRoleNames) == 0 {
						expectedRoleNames = payloadStringSliceValues(currentPermission, "all_role_names")
					}
				}
				observedRoleNames := rowStringList(currentContext, "role_names")
				if len(expectedRoleNames) > 0 && !slices.Equal(observedRoleNames, expectedRoleNames) {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-current-context-roles-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence logic-app row %q with current_identity_context.role_names %v, but the sibling permissions/rbac payloads defend %v", label, sourceID, observedRoleNames, expectedRoleNames),
						"persistence logic-apps current identity derivation",
						"persistence logic-apps should keep current identity role names aligned with the controlling rbac scope when it is visible, or the current permissions row when it is not",
					))
				}
			}
		}

		observedCapabilityStatuses := map[string]string{}
		capabilitySteps, _ := groupedRow["capability_steps"].([]any)
		for _, step := range capabilitySteps {
			stepMap, ok := step.(map[string]any)
			if !ok {
				continue
			}
			action, _ := stepMap["action"].(string)
			status, _ := stepMap["status"].(string)
			observedCapabilityStatuses[action] = status
		}
		for _, action := range []string{
			"create or modify workflow",
			"edit workflow definition",
			"attach or reuse exec ctx",
			"define or modify trigger",
			"enable workflow",
			"add or repurpose downstream actions",
		} {
			expected := persistenceExpectedLogicAppCapabilityStatus(controlOK)
			observed, ok := observedCapabilityStatuses[action]
			if !ok || observed != expected {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-capability-step-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.ReplaceAll(action, " ", "-"), "/", "-")),
					fmt.Sprintf("%s surfaced persistence logic-app row %q with capability step %q status %q, but the sibling permissions/rbac payloads defend %q", label, sourceID, action, observed, expected),
					"persistence logic-apps capability-step derivation",
					"persistence logic-apps capability step status should stay aligned with whether the current identity really has defended control of the workflow at the relevant scope",
				))
			}
		}

		strongestContext, _ := currentState["strongest_visible_execution_context"].(map[string]any)
		sourcePrincipalID, _ := sourceRow["principal_id"].(string)
		if strings.TrimSpace(sourcePrincipalID) == "" {
			if strongestContext != nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-execution-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context even though the sibling logic-apps payload does not expose an execution principal", label, sourceID),
					"persistence logic-apps execution-context derivation",
					"persistence logic-apps should only surface strongest execution context when the sibling logic-apps payload exposes an execution identity to reason about",
				))
			}
		} else {
			if strongestContext == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-execution-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s did not surface strongest_visible_execution_context for persistence logic-app row %q even though the sibling logic-apps payload exposes an execution principal", label, sourceID),
					"persistence logic-apps execution-context derivation",
					"persistence logic-apps should preserve the visible execution identity context when the sibling logic-apps payload exposes one",
				))
			} else {
				observedKind, _ := strongestContext["kind"].(string)
				if observedKind != "logic-app-execution-context" {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-execution-context-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context.kind %q", label, sourceID, observedKind),
						"persistence logic-apps execution-context derivation",
						"persistence logic-apps should mark the execution identity as logic-app-execution-context when it is reusing the sibling logic-app identity story",
					))
				}
				observedPrincipalID, _ := strongestContext["principal_id"].(string)
				if observedPrincipalID != sourcePrincipalID {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-execution-context-principal-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context.principal_id %q, but the sibling logic-apps payload reports %q", label, sourceID, observedPrincipalID, sourcePrincipalID),
						"persistence logic-apps execution-context derivation",
						"persistence logic-apps should preserve the same execution principal the sibling logic-apps payload already exposed",
					))
				}
				observedIdentityType, _ := strongestContext["identity_type"].(string)
				sourceIdentityType, _ := sourceRow["identity_type"].(string)
				if strings.TrimSpace(observedIdentityType) != strings.TrimSpace(sourceIdentityType) {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-execution-context-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context.identity_type %q, but the sibling logic-apps payload reports %q", label, sourceID, observedIdentityType, sourceIdentityType),
						"persistence logic-apps execution-context derivation",
						"persistence logic-apps should preserve the execution identity type from the sibling logic-apps payload",
					))
				}
				sourcePermission := permissionsByPrincipal[sourcePrincipalID]
				observedRoleNames := rowStringList(strongestContext, "role_names")
				observedScopeIDs := rowStringList(strongestContext, "scope_ids")
				if sourcePermission == nil {
					if len(observedRoleNames) != 0 {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-execution-context-roles-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context.role_names %v even though the sibling permissions payload shows no matching execution-principal permission row", label, sourceID, observedRoleNames),
							"persistence logic-apps execution-context derivation",
							"persistence logic-apps should leave execution-context role_names empty when the sibling permissions payload cannot match the workflow identity to Azure role context",
						))
					}
					if len(observedScopeIDs) != 0 {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-execution-context-scope-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context.scope_ids %v even though the sibling permissions payload shows no matching execution-principal permission row", label, sourceID, observedScopeIDs),
							"persistence logic-apps execution-context derivation",
							"persistence logic-apps should leave execution-context scope_ids empty when the sibling permissions payload cannot match the workflow identity to Azure role context",
						))
					}
				} else {
					expectedRoleNames := payloadStringSliceValues(sourcePermission, "high_impact_roles")
					if len(expectedRoleNames) == 0 {
						expectedRoleNames = payloadStringSliceValues(sourcePermission, "all_role_names")
					}
					expectedScopeIDs := payloadStringSliceValues(sourcePermission, "scope_ids")
					if !slices.Equal(observedRoleNames, expectedRoleNames) {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-execution-context-roles-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context.role_names %v, but the sibling permissions payload reports %v", label, sourceID, observedRoleNames, expectedRoleNames),
							"persistence logic-apps execution-context derivation",
							"persistence logic-apps should preserve the visible Azure role context for the workflow identity when the sibling permissions payload can match it",
						))
					}
					if !slices.Equal(observedScopeIDs, expectedScopeIDs) {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-execution-context-scope-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							fmt.Sprintf("%s surfaced persistence logic-app row %q with strongest_visible_execution_context.scope_ids %v, but the sibling permissions payload reports %v", label, sourceID, observedScopeIDs, expectedScopeIDs),
							"persistence logic-apps execution-context derivation",
							"persistence logic-apps should preserve the visible Azure scope context for the workflow identity when the sibling permissions payload can match it",
						))
					}
				}
			}
		}
	}

	return findings
}
