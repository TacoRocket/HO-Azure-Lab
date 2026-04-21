package lab

import (
	"fmt"
	"slices"
	"strings"
)

func findLogicAppRowByID(payload map[string]any, workflowID string) map[string]any {
	rows, _ := payload["workflows"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(workflowID) {
			return rowMap
		}
	}
	return nil
}

func findAutomationRowByID(payload map[string]any, accountID string) map[string]any {
	rows, _ := payload["automation_accounts"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(accountID) {
			return rowMap
		}
	}
	return nil
}

func automationRowIdentityIDs(row map[string]any) []string {
	values, _ := row["identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func automationRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["identity_type"].(string)
	rowPrincipalID, _ := row["principal_id"].(string)
	rowClientID, _ := row["client_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		strings.TrimSpace(rowClientID) != "" ||
		len(automationRowIdentityIDs(row)) > 0
}

func logicAppRowIdentityIDs(row map[string]any) []string {
	values, _ := row["identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func findAzureMLRowByID(payload map[string]any, workspaceID string) map[string]any {
	rows, _ := payload["workspaces"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(workspaceID) {
			return rowMap
		}
	}
	return nil
}

func findEventGridRouteRowByID(payload map[string]any, routeID string) map[string]any {
	rows, _ := payload["routes"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(routeID) {
			return rowMap
		}
	}
	return nil
}

func validateEventGridPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveEventGridContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "event-grid" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-event-grid-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live event-grid context artifact",
			"lab runner event-grid context capture",
			"event-grid validation should compare the tool payload against recorded Event Grid route truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["routes"].([]any)
	if len(rows) != len(context.Routes) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d event-grid rows, but Azure-backed validation recorded %d visible routes", label, len(rows), len(context.Routes)),
			"event-grid row selection or Azure-backed validation context",
			"event-grid should keep visible route rows aligned with the Event Grid subscriptions the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.Routes {
		row := findEventGridRouteRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-route-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible Event Grid route for id %q", label, truth.ID),
				"event-grid asset visibility or Azure-backed validation context",
				"event-grid should keep visible Event Grid subscriptions visible when the current viewpoint can enumerate them",
			))
			continue
		}

		stringFields := map[string]string{
			"route":                 truth.Name,
			"classification":        truth.Classification,
			"source_id":             truth.SourceID,
			"source_type":           truth.SourceType,
			"destination_type":      truth.DestinationType,
			"destination_target_id": truth.DestinationTargetID,
			"provisioning_state":    truth.ProvisioningState,
			"identity_type":         truth.IdentityType,
			"identity_id":           truth.IdentityID,
			"event_delivery_schema": truth.EventDeliverySchema,
		}
		for key, expected := range stringFields {
			observed, _ := row[key].(string)
			if normalizeResourceID(observed) == normalizeResourceID(expected) {
				continue
			}
			if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
				fmt.Sprintf("%s surfaced Event Grid route id %q with %s %q, but Azure reports %q", label, truth.ID, key, observed, expected),
				"event-grid field rendering or Azure-backed validation context",
				"event-grid should keep Azure-backed route fields aligned with the Event Grid subscription it is summarizing",
			))
		}

		observedExternalDelivery, _ := row["external_delivery"].(bool)
		if observedExternalDelivery != truth.ExternalDelivery {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-external-delivery-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Event Grid route id %q with external_delivery %t, but Azure reports %t", label, truth.ID, observedExternalDelivery, truth.ExternalDelivery),
				"event-grid webhook classification or Azure-backed validation context",
				"event-grid should keep webhook-style external delivery classification aligned with the visible destination type",
			))
		}

		listFields := map[string][]string{
			"included_event_types": truth.IncludedEventTypes,
			"related_ids":          truth.RelatedIDs,
		}
		for key, expected := range listFields {
			expectedSet := normalizeStringSet(expected)
			observed := rowStringList(row, key)
			observedSet := normalizeStringSet(observed)
			if len(expectedSet) == len(observedSet) {
				missing := false
				for _, expectedValue := range expected {
					if _, ok := observedSet[normalizeResourceID(expectedValue)]; ok {
						continue
					}
					if _, ok := observedSet[strings.TrimSpace(expectedValue)]; ok {
						continue
					}
					missing = true
					break
				}
				if !missing {
					continue
				}
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
				fmt.Sprintf("%s surfaced Event Grid route id %q with %s %v, but Azure-backed expectation is %v", label, truth.ID, key, observed, expected),
				"event-grid list rendering or Azure-backed validation context",
				"event-grid should keep included event types and related IDs aligned with the visible Event Grid route truth",
			))
		}
	}

	return findings
}

func validateAzureMLPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAzureMLContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "azure-ml" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-azure-ml-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live azure-ml context artifact",
			"lab runner azure-ml context capture",
			"azure-ml validation should compare the tool payload against recorded Azure ML workspace truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["workspaces"].([]any)
	if len(rows) != len(context.Workspaces) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d Azure ML workspace rows, but Azure-backed validation recorded %d visible workspaces", label, len(rows), len(context.Workspaces)),
			"azure-ml row selection or Azure-backed validation context",
			"azure-ml should keep visible workspace rows aligned with the Azure ML workspaces the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.Workspaces {
		row := findAzureMLRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-workspace-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible Azure ML workspace row for id %q", label, truth.ID),
				"azure-ml asset visibility or Azure-backed validation context",
				"azure-ml should keep visible Azure ML workspaces visible when the current viewpoint can enumerate them",
			))
			continue
		}

		stringFields := map[string]string{
			"workspace":               truth.Name,
			"classification":          truth.Classification,
			"resource_group":          truth.ResourceGroup,
			"location":                truth.Location,
			"workspace_kind":          truth.WorkspaceKind,
			"state":                   truth.State,
			"public_network_access":   truth.PublicNetworkAccess,
			"identity_type":           truth.IdentityType,
			"principal_id":            truth.PrincipalID,
			"storage_account_id":      truth.StorageAccountID,
			"key_vault_id":            truth.KeyVaultID,
			"container_registry_id":   truth.ContainerRegistryID,
			"application_insights_id": truth.ApplicationInsightsID,
		}
		for key, expected := range stringFields {
			if strings.TrimSpace(expected) == "" {
				continue
			}
			observed, _ := row[key].(string)
			if normalizeResourceID(observed) == normalizeResourceID(expected) {
				continue
			}
			if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
				fmt.Sprintf("%s surfaced Azure ML workspace id %q with %s %q, but Azure reports %q", label, truth.ID, key, observed, expected),
				"azure-ml field rendering or Azure-backed validation context",
				"azure-ml should keep Azure-backed workspace fields aligned with the workspace it is summarizing",
			))
		}

		countFields := map[string]int{
			"compute_count":   truth.ComputeCount,
			"job_count":       truth.JobCount,
			"schedule_count":  truth.ScheduleCount,
			"endpoint_count":  truth.EndpointCount,
			"datastore_count": truth.DatastoreCount,
		}
		for key, expected := range countFields {
			observed := rowIntPtr(row, key)
			if observed != nil && *observed == expected {
				continue
			}
			observedText := "<missing>"
			if observed != nil {
				observedText = fmt.Sprintf("%d", *observed)
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
				fmt.Sprintf("%s surfaced Azure ML workspace id %q with %s %s, but Azure reports %d", label, truth.ID, key, observedText, expected),
				"azure-ml count rendering or Azure-backed validation context",
				"azure-ml should keep compute, job, schedule, endpoint, and datastore counts aligned with the visible workspace truth",
			))
		}

		listFields := map[string][]string{
			"identity_ids":           truth.IdentityIDs,
			"compute_types":          truth.ComputeTypes,
			"job_types":              truth.JobTypes,
			"schedule_trigger_types": truth.ScheduleTriggerTypes,
			"endpoint_auth_modes":    truth.EndpointAuthModes,
			"endpoint_public_access": truth.EndpointPublicAccess,
			"datastore_types":        truth.DatastoreTypes,
			"related_ids":            truth.RelatedIDs,
		}
		for key, expected := range listFields {
			expectedSet := normalizeStringSet(expected)
			observed := rowStringList(row, key)
			observedSet := normalizeStringSet(observed)
			if len(expectedSet) == len(observedSet) {
				missing := false
				for _, expectedValue := range expected {
					if _, ok := observedSet[normalizeResourceID(expectedValue)]; ok {
						continue
					}
					if _, ok := observedSet[strings.TrimSpace(expectedValue)]; ok {
						continue
					}
					missing = true
					break
				}
				if !missing {
					continue
				}
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
				fmt.Sprintf("%s surfaced Azure ML workspace id %q with %s %v, but Azure-backed expectation is %v", label, truth.ID, key, observed, expected),
				"azure-ml list rendering or Azure-backed validation context",
				"azure-ml should keep identity, child-type, and related-id lists aligned with the visible Azure ML workspace truth",
			))
		}
	}

	return findings
}

func validateAutomationPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAutomationContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "automation" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-automation-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live automation context artifact",
			"lab runner automation context capture",
			"automation validation should compare the tool payload against recorded Azure Automation truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.AutomationAccounts {
		row := findAutomationRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-automation-account-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible Automation account row for id %q", label, truth.ID),
				"automation asset visibility or Azure-backed validation context",
				"automation should keep visible Automation accounts visible when the current viewpoint can enumerate them",
			))
			continue
		}

		for key, expected := range map[string]string{
			"name":           truth.Name,
			"resource_group": truth.ResourceGroup,
			"location":       truth.Location,
			"state":          truth.State,
			"sku_name":       truth.SKUName,
			"identity_type":  truth.IdentityType,
			"principal_id":   truth.PrincipalID,
			"client_id":      truth.ClientID,
		} {
			if strings.TrimSpace(expected) == "" {
				continue
			}
			observed, _ := row[key].(string)
			if strings.TrimSpace(observed) != strings.TrimSpace(expected) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s surfaced Automation account id %q with %s %q, but Azure reports %q", label, truth.ID, key, observed, expected),
					"automation field rendering or Azure-backed validation context",
					"automation should keep Azure-backed Automation account fields aligned with the account it is summarizing",
				))
			}
		}

		countFields := map[string]*int{
			"runbook_count":             truth.RunbookCount,
			"published_runbook_count":   truth.PublishedRunbookCount,
			"schedule_count":            truth.ScheduleCount,
			"job_schedule_count":        truth.JobScheduleCount,
			"webhook_count":             truth.WebhookCount,
			"hybrid_worker_group_count": truth.HybridWorkerGroupCount,
			"credential_count":          truth.CredentialCount,
			"certificate_count":         truth.CertificateCount,
			"connection_count":          truth.ConnectionCount,
			"variable_count":            truth.VariableCount,
			"encrypted_variable_count":  truth.EncryptedVariableCount,
		}
		for key, expected := range countFields {
			if expected == nil {
				continue
			}
			observed := rowIntPtr(row, key)
			if observed == nil || *observed != *expected {
				observedText := "<missing>"
				if observed != nil {
					observedText = fmt.Sprintf("%d", *observed)
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s surfaced Automation account id %q with %s %s, but Azure reports %d", label, truth.ID, key, observedText, *expected),
					"automation count rendering or Azure-backed validation context",
					"automation should keep child-object counts aligned with the visible Automation account truth",
				))
			}
		}

		if normalizeIdentityType(truth.IdentityType) == "" && len(truth.IdentityIDs) == 0 {
			if automationRowHasIdentityContext(row) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-identity-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced Automation account id %q with identity context, but Azure does not currently show identity on that account", label, truth.ID),
					"automation identity rendering or Azure-backed validation context",
					"automation should not describe an Automation account as identity-bearing when Azure shows no managed identity on that account",
				))
			}
			continue
		}
		if !automationRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Automation account id %q, but lost the Azure-visible identity context for that account", label, truth.ID),
				"automation identity rendering or Azure-backed validation context",
				"automation should preserve managed identity context when Azure shows that Automation account carrying identity configuration",
			))
			continue
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		observedIdentityIDs := normalizeStringSet(automationRowIdentityIDs(row))
		if len(expectedIdentityIDs) != len(observedIdentityIDs) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Automation account id %q with identity_ids %v, but Azure reports %v", label, truth.ID, automationRowIdentityIDs(row), truth.IdentityIDs),
				"automation identity rendering or Azure-backed validation context",
				"automation should preserve the real Automation identity IDs Azure currently exposes",
			))
		} else {
			for _, expectedIdentityID := range truth.IdentityIDs {
				if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced Automation account id %q with identity_ids %v, but Azure reports %v", label, truth.ID, automationRowIdentityIDs(row), truth.IdentityIDs),
						"automation identity rendering or Azure-backed validation context",
						"automation should preserve the real Automation identity IDs Azure currently exposes",
					))
					break
				}
			}
		}

		expectedIdentityJoinIDs := []string{}
		expectedIdentityJoinIDs = append(expectedIdentityJoinIDs, truth.IdentityIDs...)
		if strings.TrimSpace(truth.PrincipalID) != "" {
			expectedIdentityJoinIDs = append(expectedIdentityJoinIDs, truth.PrincipalID)
		}
		if strings.TrimSpace(truth.ClientID) != "" {
			expectedIdentityJoinIDs = append(expectedIdentityJoinIDs, truth.ClientID)
		}
		expectedIdentityJoinSet := normalizeStringSet(expectedIdentityJoinIDs)
		observedIdentityJoinSet := normalizeStringSet(rowStringList(row, "identity_join_ids"))
		if len(expectedIdentityJoinSet) != len(observedIdentityJoinSet) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-join-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Automation account id %q with identity_join_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "identity_join_ids"), expectedIdentityJoinIDs),
				"automation join-id rendering or Azure-backed validation context",
				"automation should keep identity_join_ids aligned with the visible identity IDs plus principal and client identifiers Azure exposes",
			))
		}

		expectedRelatedIDs := append([]string{truth.ID}, truth.IdentityIDs...)
		expectedRelatedSet := normalizeStringSet(expectedRelatedIDs)
		observedRelatedSet := normalizeStringSet(rowStringList(row, "related_ids"))
		if len(expectedRelatedSet) != len(observedRelatedSet) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Automation account id %q with related_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "related_ids"), expectedRelatedIDs),
				"automation related-id rendering or Azure-backed validation context",
				"automation should keep related_ids aligned with the Automation account and its visible identity IDs",
			))
		}
	}

	return findings
}

func validateLogicAppsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveLogicAppsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "logic-apps" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-logic-apps-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live logic apps context artifact",
			"lab runner logic apps context capture",
			"logic-apps validation should compare the tool payload against recorded Azure Logic Apps truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.Workflows {
		row := findLogicAppRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-workflow-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible Logic App row for id %q", label, truth.ID),
				"logic-apps asset visibility or Azure-backed validation context",
				"logic-apps should keep visible Logic Apps workflows visible when the current viewpoint can enumerate them",
			))
			continue
		}

		for key, expected := range map[string]string{
			"logic_app":      truth.Name,
			"resource_group": truth.ResourceGroup,
			"location":       truth.Location,
			"state":          truth.State,
			"workflow_kind":  truth.WorkflowKind,
			"classification": truth.Classification,
			"identity_type":  truth.IdentityType,
			"principal_id":   truth.PrincipalID,
			"client_id":      truth.ClientID,
		} {
			if strings.TrimSpace(expected) == "" {
				continue
			}
			observed, _ := row[key].(string)
			if strings.TrimSpace(observed) != strings.TrimSpace(expected) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s surfaced Logic App id %q with %s %q, but Azure reports %q", label, truth.ID, key, observed, expected),
					"logic-apps field rendering or Azure-backed validation context",
					"logic-apps should keep Azure-backed workflow fields aligned with the Logic App it is summarizing",
				))
			}
		}

		rowRequestTrigger, _ := row["externally_callable_request_trigger"].(bool)
		if rowRequestTrigger != truth.ExternallyCallableRequestTrigger {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-request-trigger-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Logic App id %q with externally_callable_request_trigger=%t, but Azure reports %t", label, truth.ID, rowRequestTrigger, truth.ExternallyCallableRequestTrigger),
				"logic-apps trigger rendering or Azure-backed validation context",
				"logic-apps should keep request-trigger posture aligned with the visible Logic App workflow definition",
			))
		}

		rowRecurrenceSummary, _ := row["recurrence_summary"].(string)
		if strings.TrimSpace(rowRecurrenceSummary) != strings.TrimSpace(truth.RecurrenceSummary) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-recurrence-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Logic App id %q with recurrence_summary %q, but Azure reports %q", label, truth.ID, rowRecurrenceSummary, truth.RecurrenceSummary),
				"logic-apps recurrence rendering or Azure-backed validation context",
				"logic-apps should keep recurrence summary aligned with the visible Logic App workflow definition",
			))
		}

		if !slices.Equal(rowStringList(row, "trigger_types"), truth.TriggerTypes) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-trigger-types-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Logic App id %q with trigger_types %v, but Azure reports %v", label, truth.ID, rowStringList(row, "trigger_types"), truth.TriggerTypes),
				"logic-apps trigger rendering or Azure-backed validation context",
				"logic-apps should keep trigger types aligned with the visible Logic App workflow definition",
			))
		}

		if !slices.Equal(rowStringList(row, "downstream_action_kinds"), truth.DownstreamActionKinds) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-downstream-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Logic App id %q with downstream_action_kinds %v, but Azure reports %v", label, truth.ID, rowStringList(row, "downstream_action_kinds"), truth.DownstreamActionKinds),
				"logic-apps action rendering or Azure-backed validation context",
				"logic-apps should keep downstream action kinds aligned with the visible Logic App workflow definition",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		observedIdentityIDs := normalizeStringSet(logicAppRowIdentityIDs(row))
		if len(expectedIdentityIDs) > 0 {
			if len(expectedIdentityIDs) != len(observedIdentityIDs) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-identity-ids-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced Logic App id %q with identity_ids %v, but Azure reports %v", label, truth.ID, logicAppRowIdentityIDs(row), truth.IdentityIDs),
					"logic-apps identity rendering or Azure-backed validation context",
					"logic-apps should preserve the visible Logic App identity IDs Azure currently exposes",
				))
			} else {
				for _, expectedIdentityID := range truth.IdentityIDs {
					if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-identity-ids-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							fmt.Sprintf("%s surfaced Logic App id %q with identity_ids %v, but Azure reports %v", label, truth.ID, logicAppRowIdentityIDs(row), truth.IdentityIDs),
							"logic-apps identity rendering or Azure-backed validation context",
							"logic-apps should preserve the visible Logic App identity IDs Azure currently exposes",
						))
						break
					}
				}
			}
		}
	}

	return findings
}
