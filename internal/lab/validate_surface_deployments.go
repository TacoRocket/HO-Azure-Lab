package lab

import (
	"fmt"
	"strings"
)

func findArmDeploymentRowByID(payload map[string]any, deploymentID string) map[string]any {
	rows, _ := payload["deployments"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(deploymentID) {
			return rowMap
		}
	}
	return nil
}

func findArmDeploymentFindingByID(payload map[string]any, findingID string) map[string]any {
	rows, _ := payload["findings"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if strings.TrimSpace(rowID) == strings.TrimSpace(findingID) {
			return rowMap
		}
	}
	return nil
}

func validateArmDeploymentsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveArmDeploymentsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "arm-deployments" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-arm-deployments-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live arm-deployments context artifact",
			"lab runner arm-deployments context capture",
			"arm-deployments validation should compare the tool payload against recorded ARM deployment history truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["deployments"].([]any)
	if len(rows) != len(context.Deployments) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d arm-deployments rows, but Azure-backed validation recorded %d visible deployments", label, len(rows), len(context.Deployments)),
			"arm-deployments row selection or Azure-backed validation context",
			"arm-deployments should keep visible deployment-history rows aligned with the ARM deployments the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.Deployments {
		row := findArmDeploymentRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-deployment-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible ARM deployment row for id %q", label, truth.ID),
				"arm-deployments asset visibility or Azure-backed validation context",
				"arm-deployments should keep visible Azure deployment-history rows visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkString := func(field string, expected string, equalFold bool, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if normalizeResourceID(observed) == normalizeResourceID(expected) {
				return
			}
			if equalFold {
				if strings.EqualFold(strings.TrimSpace(observed), strings.TrimSpace(expected)) {
					return
				}
			} else if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced ARM deployment id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkInt := func(field string, expected int, likelySeam string, expectedOutcome string) {
			observed, _ := row[field].(float64)
			if int(observed) == expected {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced ARM deployment id %q with %s %d, but Azure reports %d", label, truth.ID, field, int(observed), expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkString("name", truth.Name, false, "arm-deployments naming or Azure-backed validation context", "arm-deployments should keep deployment names aligned with the Azure deployment history entries it is summarizing")
		checkString("mode", truth.Mode, true, "arm-deployments mode rendering or Azure-backed validation context", "arm-deployments should keep deployment modes aligned with the ARM deployment history it is summarizing")
		checkString("scope", truth.Scope, false, "arm-deployments scope rendering or Azure-backed validation context", "arm-deployments should keep deployment scope IDs aligned with the ARM deployment history it is summarizing")
		checkString("scope_type", truth.ScopeType, false, "arm-deployments scope typing or Azure-backed validation context", "arm-deployments should keep deployment scope typing aligned with the ARM deployment history it is summarizing")
		if truth.ResourceGroup != nil {
			checkString("resource_group", *truth.ResourceGroup, true, "arm-deployments resource-group rendering or Azure-backed validation context", "arm-deployments should keep resource-group placement aligned with the ARM deployment history it is summarizing")
		}
		checkString("provisioning_state", truth.ProvisioningState, true, "arm-deployments state rendering or Azure-backed validation context", "arm-deployments should keep provisioning-state cues aligned with the ARM deployment history it is summarizing")
		if truth.TemplateLink != nil {
			checkString("template_link", *truth.TemplateLink, false, "arm-deployments template-link rendering or Azure-backed validation context", "arm-deployments should keep linked template URIs aligned with the ARM deployment history it is summarizing")
		}
		if truth.ParametersLink != nil {
			checkString("parameters_link", *truth.ParametersLink, false, "arm-deployments parameters-link rendering or Azure-backed validation context", "arm-deployments should keep linked parameters URIs aligned with the ARM deployment history it is summarizing")
		}
		checkInt("outputs_count", truth.OutputsCount, "arm-deployments output counting or Azure-backed validation context", "arm-deployments should keep output counts aligned with the ARM deployment history it is summarizing")
		checkInt("output_resource_count", truth.OutputResourceCount, "arm-deployments output-resource counting or Azure-backed validation context", "arm-deployments should keep output-resource counts aligned with the ARM deployment history it is summarizing")

		expectedProviders := normalizeLowerStringSet(truth.Providers)
		observedProviders := normalizeLowerStringSet(rowStringList(row, "providers"))
		if len(expectedProviders) != len(observedProviders) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-providers-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced ARM deployment id %q with providers %v, but Azure reports %v", label, truth.ID, rowStringList(row, "providers"), truth.Providers),
				"arm-deployments provider rendering or Azure-backed validation context",
				"arm-deployments should keep provider lists aligned with the ARM deployment history it is summarizing",
			))
		} else {
			for _, provider := range truth.Providers {
				if _, ok := observedProviders[strings.ToLower(strings.TrimSpace(provider))]; ok {
					continue
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-providers-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced ARM deployment id %q with providers %v, but Azure reports %v", label, truth.ID, rowStringList(row, "providers"), truth.Providers),
					"arm-deployments provider rendering or Azure-backed validation context",
					"arm-deployments should keep provider lists aligned with the ARM deployment history it is summarizing",
				))
				break
			}
		}

		expectedRelatedIDs := normalizeStringSet(truth.RelatedIDs)
		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		if len(expectedRelatedIDs) != len(observedRelatedIDs) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-ids-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced ARM deployment id %q with related_ids %v, but Azure reports %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
				"arm-deployments related-id rendering or Azure-backed validation context",
				"arm-deployments should keep related ID cues aligned with the ARM deployment history it is summarizing",
			))
		} else {
			for _, relatedID := range truth.RelatedIDs {
				if _, ok := observedRelatedIDs[normalizeResourceID(relatedID)]; ok {
					continue
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-related-ids-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced ARM deployment id %q with related_ids %v, but Azure reports %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
					"arm-deployments related-id rendering or Azure-backed validation context",
					"arm-deployments should keep related ID cues aligned with the ARM deployment history it is summarizing",
				))
				break
			}
		}

		failedFindingID := "arm-deployment-failed-" + truth.ID
		outputsFindingID := "arm-deployment-outputs-" + truth.ID
		remoteLinkFindingID := "arm-deployment-remote-link-" + truth.ID

		expectedFailedFinding := strings.EqualFold(strings.TrimSpace(truth.ProvisioningState), "failed") || strings.EqualFold(strings.TrimSpace(truth.ProvisioningState), "canceled")
		expectedOutputsFinding := truth.OutputsCount > 0
		expectedRemoteLinkFinding := truth.TemplateLink != nil || truth.ParametersLink != nil

		failedFinding := findArmDeploymentFindingByID(payload, failedFindingID)
		outputsFinding := findArmDeploymentFindingByID(payload, outputsFindingID)
		remoteLinkFinding := findArmDeploymentFindingByID(payload, remoteLinkFindingID)

		if expectedFailedFinding && failedFinding == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-failed-finding-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s omitted the shipped failed-deployment finding for ARM deployment id %q even though Azure reports a non-successful state", label, truth.ID),
				"arm-deployments finding rendering or Azure-backed validation context",
				"arm-deployments should emit the shipped failed-deployment finding whenever Azure reports a failed or canceled deployment",
			))
		}
		if !expectedFailedFinding && failedFinding != nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-failed-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted a failed-deployment finding for ARM deployment id %q, but Azure does not currently report a failed or canceled state", label, truth.ID),
				"arm-deployments finding rendering or Azure-backed validation context",
				"arm-deployments should not overclaim failed deployment history when Azure does not show it",
			))
		}
		if expectedOutputsFinding && outputsFinding == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-outputs-finding-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s omitted the shipped outputs finding for ARM deployment id %q even though Azure reports deployment outputs", label, truth.ID),
				"arm-deployments finding rendering or Azure-backed validation context",
				"arm-deployments should emit the shipped outputs finding whenever Azure reports deployment outputs",
			))
		}
		if !expectedOutputsFinding && outputsFinding != nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-outputs-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted an outputs finding for ARM deployment id %q, but Azure does not currently report outputs on that deployment", label, truth.ID),
				"arm-deployments finding rendering or Azure-backed validation context",
				"arm-deployments should not overclaim deployment outputs when Azure does not show them",
			))
		}
		if expectedRemoteLinkFinding && remoteLinkFinding == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-remote-link-finding-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s omitted the shipped remote-link finding for ARM deployment id %q even though Azure reports a template or parameters link", label, truth.ID),
				"arm-deployments finding rendering or Azure-backed validation context",
				"arm-deployments should emit the shipped remote-link finding whenever Azure reports linked template or parameters content",
			))
		}
		if !expectedRemoteLinkFinding && remoteLinkFinding != nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-remote-link-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted a remote-link finding for ARM deployment id %q, but Azure does not currently report linked template or parameters content", label, truth.ID),
				"arm-deployments finding rendering or Azure-backed validation context",
				"arm-deployments should not overclaim linked template content when Azure does not show it",
			))
		}
	}

	return findings
}
