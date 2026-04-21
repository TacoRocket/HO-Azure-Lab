package lab

import (
	"fmt"
	"strings"
)

func findCrossTenantRow(payload map[string]any, signalType, rowID string) map[string]any {
	rows, _ := payload["cross_tenant_paths"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowSignalType, _ := rowMap["signal_type"].(string)
		rowIDValue, _ := rowMap["id"].(string)
		if strings.TrimSpace(rowSignalType) != strings.TrimSpace(signalType) {
			continue
		}
		if strings.TrimSpace(rowIDValue) == strings.TrimSpace(rowID) {
			return rowMap
		}
	}
	return nil
}

func crossTenantIssueByCollector(payload map[string]any, collector string) map[string]any {
	issues, _ := payload["issues"].([]any)
	for _, issue := range issues {
		issueMap, ok := issue.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := issueMap["kind"].(string)
		contextMap, _ := issueMap["context"].(map[string]any)
		contextCollector, _ := contextMap["collector"].(string)
		if strings.TrimSpace(kind) == "collection_error" && strings.TrimSpace(contextCollector) == strings.TrimSpace(collector) {
			return issueMap
		}
	}
	return nil
}

func validateCrossTenantPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveCrossTenantContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "cross-tenant" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-cross-tenant-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live cross-tenant context artifact",
			"lab runner cross-tenant context capture",
			"cross-tenant validation should compare the tool payload against recorded tenant-shaped truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.ExpectedRows {
		row := findCrossTenantRow(payload, truth.SignalType, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-row-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(truth.SignalType, "_", "-")),
				fmt.Sprintf("%s did not surface the expected cross-tenant %s row %q", label, truth.SignalType, truth.Name),
				"cross-tenant row visibility or tenant-shaped validation context",
				"cross-tenant should keep visible outside-tenant and tenant-policy cues visible when the current viewpoint can read them",
			))
			continue
		}

		rowName, _ := row["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced cross-tenant row id %q as name %q, but the validation context recorded %q", label, truth.ID, rowName, truth.Name),
				"cross-tenant naming or tenant-shaped validation context",
				"cross-tenant should keep row naming aligned with the tenant-shaped evidence it is summarizing",
			))
		}

		rowAttackPath, _ := row["attack_path"].(string)
		if strings.TrimSpace(rowAttackPath) != strings.TrimSpace(truth.AttackPath) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-attack-path-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced cross-tenant row %q with attack_path %q, but the validation context recorded %q", label, truth.Name, rowAttackPath, truth.AttackPath),
				"cross-tenant attack-path rendering or tenant-shaped validation context",
				"cross-tenant should keep attack-path classification aligned with the relationship it is summarizing",
			))
		}

		rowPriority, _ := row["priority"].(string)
		if strings.TrimSpace(rowPriority) != strings.TrimSpace(truth.Priority) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-priority-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced cross-tenant row %q with priority %q, but the validation context recorded %q", label, truth.Name, rowPriority, truth.Priority),
				"cross-tenant priority rendering or tenant-shaped validation context",
				"cross-tenant should keep row priority aligned with the underlying visible relationship it is summarizing",
			))
		}

		rowScope, _ := row["scope"].(string)
		if strings.TrimSpace(truth.Scope) != "" && strings.TrimSpace(rowScope) != strings.TrimSpace(truth.Scope) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-scope-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced cross-tenant row %q with scope %q, but the validation context recorded %q", label, truth.Name, rowScope, truth.Scope),
				"cross-tenant scope rendering or tenant-shaped validation context",
				"cross-tenant should keep scope aligned with the visible tenant relationship it is summarizing",
			))
		}

		rowTenantID, _ := row["tenant_id"].(string)
		if strings.TrimSpace(truth.TenantID) != "" && strings.TrimSpace(rowTenantID) != strings.TrimSpace(truth.TenantID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-tenant-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced cross-tenant row %q with tenant_id %q, but the validation context recorded %q", label, truth.Name, rowTenantID, truth.TenantID),
				"cross-tenant tenant-id rendering or tenant-shaped validation context",
				"cross-tenant should keep tenant_id aligned with the visible tenant relationship it is summarizing",
			))
		}

		if len(truth.RelatedIDs) > 0 {
			observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
			for _, expectedRelatedID := range truth.RelatedIDs {
				if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
					continue
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-related-id-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced cross-tenant row %q with related_ids %v, but the validation context recorded %v", label, truth.Name, rowStringList(row, "related_ids"), truth.RelatedIDs),
					"cross-tenant related-id rendering or tenant-shaped validation context",
					"cross-tenant should preserve the IDs that anchor each visible tenant-boundary row",
				))
				break
			}
		}
	}

	requiredCollectors := normalizeStringSet(context.RequiredIssueCollectors)
	for _, collector := range context.RequiredIssueCollectors {
		if crossTenantIssueByCollector(payload, collector) != nil {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-%s-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.TrimSpace(collector), ".", "-")),
			fmt.Sprintf("%s did not record the expected collection_error issue for unreadable cross-tenant collector %q", label, collector),
			"cross-tenant partial-read issue reporting or tenant-shaped validation context",
			"cross-tenant should keep unreadable tenant-boundary surfaces explicit through collection_error issues instead of pretending those paths were empty",
		))
	}

	issues, _ := payload["issues"].([]any)
	for _, issue := range issues {
		issueMap, ok := issue.(map[string]any)
		if !ok {
			continue
		}
		contextMap, _ := issueMap["context"].(map[string]any)
		collector, _ := contextMap["collector"].(string)
		if !strings.HasPrefix(strings.TrimSpace(collector), "auth_policies.") && strings.TrimSpace(collector) != "cross_tenant.service_principals" {
			continue
		}
		if _, ok := requiredCollectors[normalizeResourceID(collector)]; ok {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-%s-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.TrimSpace(collector), ".", "-")),
			fmt.Sprintf("%s recorded cross-tenant issue collector %q even though the validation context did not reproduce that unreadable surface", label, collector),
			"cross-tenant partial-read issue reporting or tenant-shaped validation context",
			"cross-tenant should keep partial-read issue reporting aligned with the tenant-boundary collectors that actually failed from the current viewpoint",
		))
	}

	return findings
}
