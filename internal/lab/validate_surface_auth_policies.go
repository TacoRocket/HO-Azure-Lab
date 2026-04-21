package lab

import (
	"fmt"
	"strings"
)

var knownAuthPolicyFindingIDs = map[string]struct{}{
	"auth-policy-security-defaults-disabled":    {},
	"auth-policy-users-can-register-apps":       {},
	"auth-policy-guest-invites-everyone":        {},
	"auth-policy-risky-app-consent-enabled":     {},
	"auth-policy-user-consent-enabled":          {},
	"auth-policy-no-active-enforcement-visible": {},
}

func findAuthPolicyRow(payload map[string]any, truth liveAuthPolicyTruth) map[string]any {
	rows, _ := payload["auth_policies"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowType, _ := rowMap["policy_type"].(string)
		if strings.TrimSpace(rowType) != strings.TrimSpace(truth.PolicyType) {
			continue
		}
		rowName, _ := rowMap["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			continue
		}
		if len(truth.RelatedIDs) == 0 {
			return rowMap
		}
		observedRelatedIDs := normalizeStringSet(rowStringList(rowMap, "related_ids"))
		match := true
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
				continue
			}
			match = false
			break
		}
		if match {
			return rowMap
		}
	}
	return nil
}

func authPolicyIssueByCollector(payload map[string]any, collector string) map[string]any {
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

func authPolicyFindingByID(payload map[string]any, id string) map[string]any {
	findings, _ := payload["findings"].([]any)
	for _, finding := range findings {
		findingMap, ok := finding.(map[string]any)
		if !ok {
			continue
		}
		findingID, _ := findingMap["id"].(string)
		if strings.TrimSpace(findingID) == strings.TrimSpace(id) {
			return findingMap
		}
	}
	return nil
}

func authPolicyExpectedFindingIDs(context *liveAuthPoliciesContextArtifact) map[string]struct{} {
	expected := map[string]struct{}{}
	var securityDefaults *liveAuthPolicyTruth
	var authorizationPolicy *liveAuthPolicyTruth
	enabledConditionalAccess := 0
	for i := range context.VisiblePolicies {
		policy := &context.VisiblePolicies[i]
		switch policy.PolicyType {
		case "security-defaults":
			securityDefaults = policy
		case "authorization-policy":
			authorizationPolicy = policy
		case "conditional-access":
			if strings.EqualFold(policy.State, "enabled") {
				enabledConditionalAccess++
			}
		}
	}

	if securityDefaults != nil && strings.EqualFold(securityDefaults.State, "disabled") {
		expected["auth-policy-security-defaults-disabled"] = struct{}{}
	}
	if authorizationPolicy != nil {
		controls := normalizeLowerStringSet(authorizationPolicy.Controls)
		if _, ok := controls["users-can-register-apps"]; ok {
			expected["auth-policy-users-can-register-apps"] = struct{}{}
		}
		if _, ok := controls["guest-invites:everyone"]; ok {
			expected["auth-policy-guest-invites-everyone"] = struct{}{}
		}
		if _, ok := controls["risky-app-consent:enabled"]; ok {
			expected["auth-policy-risky-app-consent-enabled"] = struct{}{}
		} else if _, ok := controls["user-consent:self-service"]; ok {
			expected["auth-policy-user-consent-enabled"] = struct{}{}
		}
	}
	conditionalAccessUnreadable := false
	for _, collector := range context.RequiredIssueCollectors {
		if collector == "auth_policies.conditional_access" {
			conditionalAccessUnreadable = true
			break
		}
	}
	if securityDefaults != nil && strings.EqualFold(securityDefaults.State, "disabled") && enabledConditionalAccess == 0 && !conditionalAccessUnreadable {
		expected["auth-policy-no-active-enforcement-visible"] = struct{}{}
	}
	return expected
}

func validateAuthPoliciesPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAuthPoliciesContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "auth-policies" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-auth-policies-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live auth-policies context artifact",
			"lab runner auth-policies context capture",
			"auth-policies validation should compare the tool payload against recorded Graph-backed policy truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["auth_policies"].([]any)
	if len(rows) != len(context.VisiblePolicies) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d auth-policies rows, but the current Graph-backed validation context recorded %d visible policy rows", label, len(rows), len(context.VisiblePolicies)),
			"auth-policies row visibility or Graph-backed validation context",
			"auth-policies should keep visible policy rows aligned with the policy surfaces the current viewpoint can actually read",
		))
	}

	for _, truth := range context.VisiblePolicies {
		row := findAuthPolicyRow(payload, truth)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-policy-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the visible %s policy row %q", label, truth.PolicyType, truth.Name),
				"auth-policies row visibility or Graph-backed validation context",
				"auth-policies should keep visible tenant auth-policy rows visible when the current viewpoint can read them",
			))
			continue
		}

		rowState, _ := row["state"].(string)
		if strings.TrimSpace(rowState) != strings.TrimSpace(truth.State) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-state-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced auth policy %q with state %q, but Graph reports %q", label, truth.Name, rowState, truth.State),
				"auth-policies state rendering or Graph-backed validation context",
				"auth-policies should keep policy state aligned with the Graph policy surface it is summarizing",
			))
		}

		rowScope, _ := row["scope"].(string)
		if strings.TrimSpace(truth.Scope) != "" && strings.TrimSpace(rowScope) != strings.TrimSpace(truth.Scope) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-scope-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced auth policy %q with scope %q, but Graph reports %q", label, truth.Name, rowScope, truth.Scope),
				"auth-policies scope rendering or Graph-backed validation context",
				"auth-policies should keep policy scope aligned with the Graph policy surface it is summarizing",
			))
		}

		expectedControls := normalizeLowerStringSet(truth.Controls)
		observedControls := normalizeLowerStringSet(rowStringList(row, "controls"))
		if len(expectedControls) != len(observedControls) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-controls-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced auth policy %q with controls %v, but Graph-backed truth is %v", label, truth.Name, rowStringList(row, "controls"), truth.Controls),
				"auth-policies control rendering or Graph-backed validation context",
				"auth-policies should keep visible policy controls aligned with the Graph policy surface they summarize",
			))
		} else {
			for _, expectedControl := range truth.Controls {
				if _, ok := observedControls[strings.ToLower(strings.TrimSpace(expectedControl))]; ok {
					continue
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-controls-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced auth policy %q with controls %v, but Graph-backed truth is %v", label, truth.Name, rowStringList(row, "controls"), truth.Controls),
					"auth-policies control rendering or Graph-backed validation context",
					"auth-policies should keep visible policy controls aligned with the Graph policy surface they summarize",
				))
				break
			}
		}
	}

	requiredCollectors := normalizeStringSet(context.RequiredIssueCollectors)
	for _, collector := range context.RequiredIssueCollectors {
		if authPolicyIssueByCollector(payload, collector) != nil {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-%s-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.TrimSpace(collector), ".", "-")),
			fmt.Sprintf("%s did not record the expected collection_error issue for unreadable auth-policies collector %q", label, collector),
			"auth-policies partial-read issue reporting or Graph-backed validation context",
			"auth-policies should keep unreadable tenant policy surfaces explicit through collection_error issues instead of pretending the policy surface was empty",
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
		if !strings.HasPrefix(strings.TrimSpace(collector), "auth_policies.") {
			continue
		}
		if _, ok := requiredCollectors[normalizeResourceID(collector)]; ok {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-%s-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.TrimSpace(collector), ".", "-")),
			fmt.Sprintf("%s recorded auth-policies issue collector %q even though the Graph-backed validation context did not reproduce that unreadable surface", label, collector),
			"auth-policies partial-read issue reporting or Graph-backed validation context",
			"auth-policies should keep partial-read issues aligned with the policy collectors that actually failed from the current viewpoint",
		))
	}

	expectedFindingIDs := authPolicyExpectedFindingIDs(context)
	for findingID := range expectedFindingIDs {
		if authPolicyFindingByID(payload, findingID) != nil {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-%s-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(findingID, "_", "-")),
			fmt.Sprintf("%s omitted the shipped auth-policies finding %q even though the visible policy controls support it", label, findingID),
			"auth-policies finding rendering or Graph-backed validation context",
			"auth-policies should keep findings aligned with the visible tenant auth controls and the partial-read boundaries they imply",
		))
	}

	payloadFindings, _ := payload["findings"].([]any)
	for _, finding := range payloadFindings {
		findingMap, ok := finding.(map[string]any)
		if !ok {
			continue
		}
		findingID, _ := findingMap["id"].(string)
		if _, ok := knownAuthPolicyFindingIDs[strings.TrimSpace(findingID)]; !ok {
			continue
		}
		if _, ok := expectedFindingIDs[strings.TrimSpace(findingID)]; ok {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-%s-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.TrimSpace(findingID), "_", "-")),
			fmt.Sprintf("%s emitted auth-policies finding %q even though the visible policy truth in this viewpoint does not support it", label, findingID),
			"auth-policies finding rendering or Graph-backed validation context",
			"auth-policies should not overclaim tenant auth-policy findings when the current visible controls do not support them",
		))
	}

	return findings
}
