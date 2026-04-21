package lab

import (
	"fmt"
	"strings"
)

func findFunctionAppRowByID(payload map[string]any, functionID string) map[string]any {
	rows, _ := payload["function_apps"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(functionID) {
			return rowMap
		}
	}
	return nil
}

func functionAppRowIdentityIDs(row map[string]any) []string {
	values, _ := row["workload_identity_ids"].([]any)
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

func functionAppRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["workload_identity_type"].(string)
	rowPrincipalID, _ := row["workload_principal_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		len(functionAppRowIdentityIDs(row)) > 0
}

func findContainerAppRowByID(payload map[string]any, containerAppID string) map[string]any {
	rows, _ := payload["container_apps"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(containerAppID) {
			return rowMap
		}
	}
	return nil
}

func containerAppRowIdentityIDs(row map[string]any) []string {
	values, _ := row["workload_identity_ids"].([]any)
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

func containerAppRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["workload_identity_type"].(string)
	rowPrincipalID, _ := row["workload_principal_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		len(containerAppRowIdentityIDs(row)) > 0
}

func validateContainerAppsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveContainerAppsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "container-apps" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-container-apps-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live container apps context artifact",
			"lab runner container apps context capture",
			"container-apps validation should compare the tool payload against recorded Azure Container Apps truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.ContainerApps {
		row := findContainerAppRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-container-app-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible Container App row for id %q", label, truth.ID),
				"container-apps asset visibility or Azure-backed validation context",
				"container-apps should keep visible Azure Container App assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowName, _ := row["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q as name %q, but Azure reports %q", label, truth.ID, rowName, truth.Name),
				"container-apps naming or Azure-backed validation context",
				"container-apps should keep the Container App name aligned with the Azure asset it is summarizing",
			))
		}

		rowHostname, _ := row["default_hostname"].(string)
		if strings.TrimSpace(truth.DefaultHostname) != "" && strings.TrimSpace(rowHostname) != strings.TrimSpace(truth.DefaultHostname) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-hostname-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q with hostname %q, but Azure reports %q", label, truth.ID, rowHostname, truth.DefaultHostname),
				"container-apps hostname rendering or Azure-backed validation context",
				"container-apps should keep the visible hostname aligned with the Azure Container App truth",
			))
		}

		rowEnvironmentID, _ := row["environment_id"].(string)
		if strings.TrimSpace(truth.EnvironmentID) != "" && normalizeResourceID(rowEnvironmentID) != normalizeResourceID(truth.EnvironmentID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-environment-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q with environment_id %q, but Azure reports %q", label, truth.ID, rowEnvironmentID, truth.EnvironmentID),
				"container-apps environment linkage or Azure-backed validation context",
				"container-apps should keep the managed environment linkage aligned with the Azure Container App it is summarizing",
			))
		}

		rowExternalIngress := rowBoolPtr(row, "external_ingress_enabled")
		if truth.ExternalIngress != nil {
			observedExternalIngress := "<missing>"
			if rowExternalIngress != nil {
				observedExternalIngress = fmt.Sprintf("%v", *rowExternalIngress)
			}
			if rowExternalIngress == nil || *rowExternalIngress != *truth.ExternalIngress {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-external-ingress-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced Container App id %q with external_ingress_enabled %s, but Azure reports %v", label, truth.ID, observedExternalIngress, *truth.ExternalIngress),
					"container-apps ingress posture or Azure-backed validation context",
					"container-apps should keep the external ingress posture aligned with the Azure Container App it is summarizing",
				))
			}
		}

		rowTargetPort := rowIntPtr(row, "ingress_target_port")
		if truth.IngressTargetPort != nil {
			observedTargetPort := "<missing>"
			if rowTargetPort != nil {
				observedTargetPort = fmt.Sprintf("%d", *rowTargetPort)
			}
			if rowTargetPort == nil || *rowTargetPort != *truth.IngressTargetPort {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-target-port-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced Container App id %q with ingress_target_port %s, but Azure reports %d", label, truth.ID, observedTargetPort, *truth.IngressTargetPort),
					"container-apps ingress target port or Azure-backed validation context",
					"container-apps should keep the ingress target port aligned with the Azure Container App it is summarizing",
				))
			}
		}

		rowTransport, _ := row["ingress_transport"].(string)
		if strings.TrimSpace(truth.IngressTransport) != "" && !strings.EqualFold(strings.TrimSpace(rowTransport), strings.TrimSpace(truth.IngressTransport)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-transport-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q with ingress_transport %q, but Azure reports %q", label, truth.ID, rowTransport, truth.IngressTransport),
				"container-apps ingress transport or Azure-backed validation context",
				"container-apps should keep the ingress transport aligned with the Azure Container App it is summarizing",
			))
		}

		rowRevisionMode, _ := row["revision_mode"].(string)
		if strings.TrimSpace(truth.RevisionMode) != "" && !strings.EqualFold(strings.TrimSpace(rowRevisionMode), strings.TrimSpace(truth.RevisionMode)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-revision-mode-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q with revision_mode %q, but Azure reports %q", label, truth.ID, rowRevisionMode, truth.RevisionMode),
				"container-apps revision mode or Azure-backed validation context",
				"container-apps should keep the revision mode aligned with the Azure Container App it is summarizing",
			))
		}

		rowLatestReadyRevision, _ := row["latest_ready_revision_name"].(string)
		if strings.TrimSpace(truth.LatestReadyRevision) != "" && strings.TrimSpace(rowLatestReadyRevision) != strings.TrimSpace(truth.LatestReadyRevision) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-latest-ready-revision-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q with latest_ready_revision_name %q, but Azure reports %q", label, truth.ID, rowLatestReadyRevision, truth.LatestReadyRevision),
				"container-apps latest ready revision or Azure-backed validation context",
				"container-apps should keep the latest ready revision aligned with the Azure Container App it is summarizing",
			))
		}

		rowLatestRevision, _ := row["latest_revision_name"].(string)
		if strings.TrimSpace(truth.LatestRevision) != "" && strings.TrimSpace(rowLatestRevision) != strings.TrimSpace(truth.LatestRevision) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-latest-revision-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q with latest_revision_name %q, but Azure reports %q", label, truth.ID, rowLatestRevision, truth.LatestRevision),
				"container-apps latest revision or Azure-backed validation context",
				"container-apps should keep the latest revision aligned with the Azure Container App it is summarizing",
			))
		}

		if normalizeIdentityType(truth.IdentityType) == "" && len(truth.IdentityIDs) == 0 {
			if containerAppRowHasIdentityContext(row) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-identity-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced Container App id %q with managed identity context, but Azure does not currently show identity on that container app", label, truth.ID),
					"container-apps identity rendering or Azure-backed validation context",
					"container-apps should not describe a Container App as identity-bearing when Azure shows no managed identity on that app",
				))
			}
			continue
		}
		if !containerAppRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q, but lost the Azure-visible identity context for that container app", label, truth.ID),
				"container-apps identity rendering or Azure-backed validation context",
				"container-apps should preserve managed identity context when Azure shows that Container App carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["workload_identity_type"].(string)
		if normalizeIdentityType(truth.IdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.IdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Container App id %q with workload_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.IdentityType),
				"container-apps identity typing or Azure-backed validation context",
				"container-apps should keep Container App identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		if len(expectedIdentityIDs) == 0 {
			continue
		}
		observedIdentityIDs := normalizeStringSet(containerAppRowIdentityIDs(row))
		missingIdentityIDs := []string{}
		for _, expectedIdentityID := range truth.IdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
				missingIdentityIDs = append(missingIdentityIDs, expectedIdentityID)
			}
		}
		if len(missingIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s lost Azure-visible Container App identity IDs for id %q: %s", label, truth.ID, strings.Join(missingIdentityIDs, ", ")),
				"container-apps user-assigned identity rendering or Azure-backed validation context",
				"container-apps should preserve the user-assigned identity IDs Azure currently shows on visible Container App assets",
			))
		}
	}
	return findings
}

func validateFunctionsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveFunctionsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "functions" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-functions-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live functions context artifact",
			"lab runner functions context capture",
			"functions validation should compare the tool payload against recorded Azure Function App truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.FunctionApps {
		row := findFunctionAppRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-function-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible Function App row for id %q", label, truth.ID),
				"functions asset visibility or Azure-backed validation context",
				"functions should keep visible Azure Function App assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowName, _ := row["function_app"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Function App id %q as name %q, but Azure reports %q", label, truth.ID, rowName, truth.Name),
				"functions naming or Azure-backed validation context",
				"functions should keep the Function App name aligned with the Azure asset it is summarizing",
			))
		}

		rowHostname, _ := row["hostname"].(string)
		if strings.TrimSpace(truth.Hostname) != "" && strings.TrimSpace(rowHostname) != strings.TrimSpace(truth.Hostname) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-hostname-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Function App id %q with hostname %q, but Azure reports %q", label, truth.ID, rowHostname, truth.Hostname),
				"functions hostname rendering or Azure-backed validation context",
				"functions should keep the visible hostname aligned with the Azure Function App truth",
			))
		}

		rowPublicNetworkAccess, _ := row["public_network_access"].(string)
		if strings.TrimSpace(truth.PublicNetworkAccess) != "" && !strings.EqualFold(strings.TrimSpace(rowPublicNetworkAccess), strings.TrimSpace(truth.PublicNetworkAccess)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-public-network-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Function App id %q with public_network_access %q, but Azure reports %q", label, truth.ID, rowPublicNetworkAccess, truth.PublicNetworkAccess),
				"functions public network posture or Azure-backed validation context",
				"functions should keep the public network posture aligned with the Azure Function App it is summarizing",
			))
		}

		if normalizeIdentityType(truth.IdentityType) == "" && len(truth.IdentityIDs) == 0 {
			if functionAppRowHasIdentityContext(row) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-identity-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced Function App id %q with managed identity context, but Azure does not currently show identity on that function app", label, truth.ID),
					"functions identity rendering or Azure-backed validation context",
					"functions should not describe a Function App as identity-bearing when Azure shows no managed identity on that app",
				))
			}
			continue
		}
		if !functionAppRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Function App id %q, but lost the Azure-visible identity context for that function app", label, truth.ID),
				"functions identity rendering or Azure-backed validation context",
				"functions should preserve managed identity context when Azure shows that Function App carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["workload_identity_type"].(string)
		if normalizeIdentityType(truth.IdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.IdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Function App id %q with workload_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.IdentityType),
				"functions identity typing or Azure-backed validation context",
				"functions should keep Function App identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		if len(expectedIdentityIDs) == 0 {
			continue
		}
		observedIdentityIDs := normalizeStringSet(functionAppRowIdentityIDs(row))
		missingIdentityIDs := []string{}
		for _, expectedIdentityID := range truth.IdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
				missingIdentityIDs = append(missingIdentityIDs, expectedIdentityID)
			}
		}
		if len(missingIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s lost Azure-visible Function App identity IDs for id %q: %s", label, truth.ID, strings.Join(missingIdentityIDs, ", ")),
				"functions user-assigned identity rendering or Azure-backed validation context",
				"functions should preserve the user-assigned identity IDs Azure currently shows on visible Function App assets",
			))
		}
	}
	return findings
}
