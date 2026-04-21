package lab

import (
	"fmt"
	"strings"
)

func findRoleTrustRow(payload map[string]any, trustType, sourceObjectID, targetObjectID string) map[string]any {
	rows, _ := payload["trusts"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowTrustType, _ := rowMap["trust_type"].(string)
		rowSourceObjectID, _ := rowMap["source_object_id"].(string)
		rowTargetObjectID, _ := rowMap["target_object_id"].(string)
		if strings.TrimSpace(rowTrustType) != strings.TrimSpace(trustType) {
			continue
		}
		if normalizeResourceID(rowSourceObjectID) != normalizeResourceID(sourceObjectID) {
			continue
		}
		if normalizeResourceID(rowTargetObjectID) != normalizeResourceID(targetObjectID) {
			continue
		}
		return rowMap
	}
	return nil
}

func roleTrustIssueByCollector(payload map[string]any, collector string) map[string]any {
	issues, _ := payload["issues"].([]any)
	for _, issue := range issues {
		issueMap, ok := issue.(map[string]any)
		if !ok {
			continue
		}
		contextMap, _ := issueMap["context"].(map[string]any)
		contextCollector, _ := contextMap["collector"].(string)
		if strings.TrimSpace(contextCollector) == strings.TrimSpace(collector) {
			return issueMap
		}
	}
	return nil
}

func validateRoleTrustsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveRoleTrustsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "role-trusts" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-role-trusts-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live role-trusts context artifact",
			"lab runner role-trusts context capture",
			"role-trusts validation should compare the tool payload against recorded Entra trust truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["trusts"].([]any)

	if context.ExpectZeroRows {
		if len(rows) != 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-expected-empty-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced %d role-trusts rows, but the current reduced-viewpoint lab posture expects none", label, len(rows)),
				"role-trusts reduced-view visibility or Entra-backed validation context",
				"role-trusts should keep reduced viewpoints honestly empty when they cannot enumerate the backing service-principal census",
			))
		}
		for _, collector := range context.RequiredIssueCollectors {
			if roleTrustIssueByCollector(payload, collector) != nil {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-%s-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(collector, ".", "-")),
				fmt.Sprintf("%s did not record the expected collection_error issue for unreadable role-trusts collector %q", label, collector),
				"role-trusts reduced-view error reporting or Entra-backed validation context",
				"role-trusts should make unreadable trust census paths explicit instead of pretending the tenant has no trust edges",
			))
		}
		return findings
	}

	for _, truth := range context.ExpectedTrusts {
		row := findRoleTrustRow(payload, truth.TrustType, truth.SourceObjectID, truth.TargetObjectID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(truth.TrustType, "_", "-")),
				fmt.Sprintf("%s did not surface the expected role-trust row %q -> %q (%s)", label, truth.SourceObjectID, truth.TargetObjectID, truth.TrustType),
				"role-trusts trust-edge rendering or Entra-backed validation context",
				"role-trusts should keep the canary ownership, federation, and app-role trust edges visible when the current viewpoint can read them",
			))
			continue
		}

		rowSourceType, _ := row["source_type"].(string)
		if strings.TrimSpace(truth.SourceType) != "" && strings.TrimSpace(rowSourceType) != strings.TrimSpace(truth.SourceType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-source-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced role-trust row %q -> %q with source_type %q, but the validation context recorded %q", label, truth.SourceObjectID, truth.TargetObjectID, rowSourceType, truth.SourceType),
				"role-trusts source typing or Entra-backed validation context",
				"role-trusts should keep source object typing aligned with the visible Entra trust edge",
			))
		}

		rowTargetType, _ := row["target_type"].(string)
		if strings.TrimSpace(truth.TargetType) != "" && strings.TrimSpace(rowTargetType) != strings.TrimSpace(truth.TargetType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-target-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced role-trust row %q -> %q with target_type %q, but the validation context recorded %q", label, truth.SourceObjectID, truth.TargetObjectID, rowTargetType, truth.TargetType),
				"role-trusts target typing or Entra-backed validation context",
				"role-trusts should keep target object typing aligned with the visible Entra trust edge",
			))
		}

		rowEvidenceType, _ := row["evidence_type"].(string)
		if strings.TrimSpace(rowEvidenceType) != strings.TrimSpace(truth.EvidenceType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-evidence-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced role-trust row %q -> %q with evidence_type %q, but the validation context recorded %q", label, truth.SourceObjectID, truth.TargetObjectID, rowEvidenceType, truth.EvidenceType),
				"role-trusts evidence typing or Entra-backed validation context",
				"role-trusts should keep each trust row anchored to the Graph evidence type that produced it",
			))
		}

		rowConfidence, _ := row["confidence"].(string)
		if strings.TrimSpace(rowConfidence) != strings.TrimSpace(truth.Confidence) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-confidence-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced role-trust row %q -> %q with confidence %q, but the validation context recorded %q", label, truth.SourceObjectID, truth.TargetObjectID, rowConfidence, truth.Confidence),
				"role-trusts confidence rendering or Entra-backed validation context",
				"role-trusts should keep trust confidence aligned with the underlying visible evidence path",
			))
		}

		rowControlPrimitive, _ := row["control_primitive"].(string)
		if strings.TrimSpace(truth.ControlPrimitive) != "" && strings.TrimSpace(rowControlPrimitive) != strings.TrimSpace(truth.ControlPrimitive) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-control-primitive-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced role-trust row %q -> %q with control_primitive %q, but the validation context recorded %q", label, truth.SourceObjectID, truth.TargetObjectID, rowControlPrimitive, truth.ControlPrimitive),
				"role-trusts control-primitive rendering or Entra-backed validation context",
				"role-trusts should keep control-primitive labeling aligned with the visible trust edge",
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
					fmt.Sprintf("%s surfaced role-trust row %q -> %q with related_ids %v, but the validation context recorded %v", label, truth.SourceObjectID, truth.TargetObjectID, rowStringList(row, "related_ids"), truth.RelatedIDs),
					"role-trusts related-id rendering or Entra-backed validation context",
					"role-trusts should preserve the IDs that anchor each canary trust edge",
				))
				break
			}
		}

		rowSummary, _ := row["summary"].(string)
		for _, requiredSnippet := range truth.SummaryContains {
			if strings.Contains(rowSummary, requiredSnippet) {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-summary-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced role-trust row %q -> %q without the expected summary snippet %q", label, truth.SourceObjectID, truth.TargetObjectID, requiredSnippet),
				"role-trusts operator summary rendering or Entra-backed validation context",
				"role-trusts should preserve the key issuer and subject evidence it uses to explain the visible federated trust path",
			))
		}
	}

	requiredCollectors := normalizeStringSet(context.RequiredIssueCollectors)
	issues, _ := payload["issues"].([]any)
	for _, issue := range issues {
		issueMap, ok := issue.(map[string]any)
		if !ok {
			continue
		}
		contextMap, _ := issueMap["context"].(map[string]any)
		collector, _ := contextMap["collector"].(string)
		if !strings.HasPrefix(strings.TrimSpace(collector), "role_trusts.") {
			continue
		}
		if _, ok := requiredCollectors[normalizeResourceID(collector)]; ok {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-%s-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(collector, ".", "-")),
			fmt.Sprintf("%s recorded role-trusts issue collector %q even though the validation context did not reproduce that unreadable surface", label, collector),
			"role-trusts partial-read issue reporting or Entra-backed validation context",
			"role-trusts should keep issue reporting aligned with the trust collectors that actually failed from the current viewpoint",
		))
	}

	return findings
}
