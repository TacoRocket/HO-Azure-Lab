package lab

import (
	"fmt"
	"strings"
)

type expectedResourceTrust struct {
	Confidence      string
	Exposure        string
	RelatedIDs      []string
	ResourceID      string
	ResourceName    string
	ResourceType    string
	SummaryContains []string
	Target          string
	TrustType       string
}

func findResourceTrustRow(payload map[string]any, resourceID, trustType string) map[string]any {
	rows, _ := payload["resource_trusts"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowResourceID, _ := rowMap["resource_id"].(string)
		rowTrustType, _ := rowMap["trust_type"].(string)
		if normalizeResourceID(rowResourceID) != normalizeResourceID(resourceID) {
			continue
		}
		if strings.TrimSpace(rowTrustType) != strings.TrimSpace(trustType) {
			continue
		}
		return rowMap
	}
	return nil
}

func resourceTrustFindingByID(payload map[string]any, findingID string) map[string]any {
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

func validateResourceTrustsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, storageContext *liveStorageContextArtifact, keyVaultContext *liveKeyVaultContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "resource-trusts" {
		return nil
	}
	if storageContext == nil || keyVaultContext == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-resource-trusts-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record both live storage and keyvault context artifacts",
			"lab runner resource-trusts context capture",
			"resource-trusts validation should compare the composed tool payload against recorded Azure storage and Key Vault truth instead of remembered rows",
		)}
	}

	expectedTrusts := expectedResourceTrustsFromContexts(storageContext, keyVaultContext)
	findings := []Finding{}
	rows, _ := payload["resource_trusts"].([]any)
	if len(rows) != len(expectedTrusts) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d resource-trust rows, but the composed Azure-backed validation context recorded %d expected rows", label, len(rows), len(expectedTrusts)),
			"resource-trusts row selection or composed storage-plus-keyvault validation context",
			"resource-trusts should keep the composed storage and Key Vault trust rows aligned with the visible Azure-backed posture for the current viewpoint",
		))
	}

	expectedKeys := map[string]expectedResourceTrust{}
	for _, truth := range expectedTrusts {
		key := normalizeResourceID(truth.ResourceID) + "::" + strings.TrimSpace(truth.TrustType)
		expectedKeys[key] = truth

		row := findResourceTrustRow(payload, truth.ResourceID, truth.TrustType)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(truth.TrustType, "_", "-")),
				fmt.Sprintf("%s did not surface the expected resource-trust row %q (%s)", label, truth.ResourceID, truth.TrustType),
				"resource-trusts row rendering or composed storage-plus-keyvault validation context",
				"resource-trusts should keep each visible storage and Key Vault trust path aligned with the Azure-backed posture it is summarizing",
			))
			continue
		}

		checkString := func(field string, expected string, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced resource-trust row %q (%s) with %s %q, but the validation context recorded %q", label, truth.ResourceID, truth.TrustType, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkString("resource_name", truth.ResourceName, "resource-trusts naming or composed storage-plus-keyvault validation context", "resource-trusts should keep resource naming aligned with the Azure asset it is summarizing")
		checkString("resource_type", truth.ResourceType, "resource-trusts type rendering or composed storage-plus-keyvault validation context", "resource-trusts should keep resource typing aligned with the Azure asset it is summarizing")
		checkString("target", truth.Target, "resource-trusts target rendering or composed storage-plus-keyvault validation context", "resource-trusts should keep target labeling aligned with the visible network trust path")
		checkString("exposure", truth.Exposure, "resource-trusts exposure rendering or composed storage-plus-keyvault validation context", "resource-trusts should keep exposure ranking aligned with the visible Azure network posture")
		checkString("confidence", truth.Confidence, "resource-trusts confidence rendering or composed storage-plus-keyvault validation context", "resource-trusts should keep confidence aligned with the directly visible Azure posture it is summarizing")

		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced resource-trust row %q (%s) with related_ids %v, but the validation context recorded %v", label, truth.ResourceID, truth.TrustType, rowStringList(row, "related_ids"), truth.RelatedIDs),
				"resource-trusts related-id rendering or composed storage-plus-keyvault validation context",
				"resource-trusts should preserve the visible resource IDs that anchor each composed trust row",
			))
			break
		}

		rowSummary, _ := row["summary"].(string)
		for _, snippet := range truth.SummaryContains {
			if strings.Contains(rowSummary, snippet) {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-summary-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced resource-trust row %q (%s) without the expected summary snippet %q", label, truth.ResourceID, truth.TrustType, snippet),
				"resource-trusts operator summary rendering or composed storage-plus-keyvault validation context",
				"resource-trusts should preserve the key network-path wording that explains why the trust row matters",
			))
		}
	}

	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowResourceID, _ := rowMap["resource_id"].(string)
		rowTrustType, _ := rowMap["trust_type"].(string)
		key := normalizeResourceID(rowResourceID) + "::" + strings.TrimSpace(rowTrustType)
		if _, ok := expectedKeys[key]; ok {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced unexpected resource-trust row %q (%s) that the composed validation context did not reproduce", label, rowResourceID, rowTrustType),
			"resource-trusts row selection or composed storage-plus-keyvault validation context",
			"resource-trusts should not invent storage or Key Vault trust rows that do not match the visible Azure-backed posture",
		))
	}

	expectedFindingIDs := expectedResourceTrustFindingIDs(storageContext, keyVaultContext)
	for findingID := range expectedFindingIDs {
		if resourceTrustFindingByID(payload, findingID) != nil {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-%s-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(findingID, "/", "-")),
			fmt.Sprintf("%s omitted the expected composed finding %q", label, findingID),
			"resource-trusts findings rendering or composed storage-plus-keyvault validation context",
			"resource-trusts should preserve the shipped storage and Key Vault network findings that explain the visible trust rows",
		))
	}

	payloadFindings, _ := payload["findings"].([]any)
	for _, finding := range payloadFindings {
		findingMap, ok := finding.(map[string]any)
		if !ok {
			continue
		}
		findingID, _ := findingMap["id"].(string)
		if strings.HasPrefix(strings.TrimSpace(findingID), "keyvault-purge-protection-disabled-") {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-purge-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted Key Vault purge-protection finding %q inside resource-trusts", label, findingID),
				"resource-trusts findings composition or composed storage-plus-keyvault validation context",
				"resource-trusts should stay on the composed storage-plus-keyvault exposure path without purge-protection bleed-through",
			))
			continue
		}
		if _, ok := expectedFindingIDs[findingID]; ok {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(findingID), "storage-") || strings.HasPrefix(strings.TrimSpace(findingID), "keyvault-") {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted unexpected composed finding %q that the validation context did not reproduce", label, findingID),
				"resource-trusts findings composition or composed storage-plus-keyvault validation context",
				"resource-trusts should keep the composed storage and Key Vault findings aligned with the visible Azure-backed posture",
			))
		}
	}

	return findings
}

func expectedResourceTrustsFromContexts(storageContext *liveStorageContextArtifact, keyVaultContext *liveKeyVaultContextArtifact) []expectedResourceTrust {
	expected := []expectedResourceTrust{}

	for _, truth := range storageContext.StorageAssets {
		if truth.PublicAccess {
			expected = append(expected, expectedResourceTrust{
				Confidence:      "confirmed",
				Exposure:        "high",
				RelatedIDs:      []string{truth.ID},
				ResourceID:      truth.ID,
				ResourceName:    truth.Name,
				ResourceType:    "StorageAccount",
				SummaryContains: []string{"public network"},
				Target:          "public-network",
				TrustType:       "anonymous-blob-access",
			})
		}
		if strings.EqualFold(strings.TrimSpace(truth.NetworkDefaultAction), "Allow") {
			expected = append(expected, expectedResourceTrust{
				Confidence:      "confirmed",
				Exposure:        "medium",
				RelatedIDs:      []string{truth.ID},
				ResourceID:      truth.ID,
				ResourceName:    truth.Name,
				ResourceType:    "StorageAccount",
				SummaryContains: []string{"accepts public network traffic by default"},
				Target:          "public-network",
				TrustType:       "public-network-default",
			})
		}
		if truth.PrivateEndpointEnabled {
			expected = append(expected, expectedResourceTrust{
				Confidence:      "confirmed",
				Exposure:        "restricted",
				RelatedIDs:      []string{truth.ID},
				ResourceID:      truth.ID,
				ResourceName:    truth.Name,
				ResourceType:    "StorageAccount",
				SummaryContains: []string{"private endpoint path", "Private Link"},
				Target:          "private-link",
				TrustType:       "private-endpoint",
			})
		}
	}

	for _, truth := range keyVaultContext.KeyVaults {
		if strings.EqualFold(strings.TrimSpace(truth.PublicNetworkAccess), "Enabled") {
			exposure := "medium"
			if strings.EqualFold(strings.TrimSpace(truth.NetworkDefaultAction), "Allow") || strings.TrimSpace(truth.NetworkDefaultAction) == "" {
				exposure = "high"
			}
			expected = append(expected, expectedResourceTrust{
				Confidence:      "confirmed",
				Exposure:        exposure,
				RelatedIDs:      []string{truth.ID},
				ResourceID:      truth.ID,
				ResourceName:    truth.Name,
				ResourceType:    "KeyVault",
				SummaryContains: []string{"public network path"},
				Target:          "public-network",
				TrustType:       "public-network",
			})
		}
		if truth.PrivateEndpointEnabled {
			expected = append(expected, expectedResourceTrust{
				Confidence:      "confirmed",
				Exposure:        "restricted",
				RelatedIDs:      []string{truth.ID},
				ResourceID:      truth.ID,
				ResourceName:    truth.Name,
				ResourceType:    "KeyVault",
				SummaryContains: []string{"private endpoint path", "Private Link"},
				Target:          "private-link",
				TrustType:       "private-endpoint",
			})
		}
	}

	return expected
}

func expectedResourceTrustFindingIDs(storageContext *liveStorageContextArtifact, keyVaultContext *liveKeyVaultContextArtifact) map[string]struct{} {
	expected := map[string]struct{}{}

	for _, truth := range storageContext.StorageAssets {
		if truth.PublicAccess {
			expected["storage-public-"+truth.ID] = struct{}{}
		}
		if strings.EqualFold(strings.TrimSpace(truth.NetworkDefaultAction), "Allow") {
			expected["storage-firewall-open-"+truth.ID] = struct{}{}
		}
	}

	for _, truth := range keyVaultContext.KeyVaults {
		publicEnabled := strings.EqualFold(strings.TrimSpace(truth.PublicNetworkAccess), "Enabled")
		defaultAction := strings.TrimSpace(truth.NetworkDefaultAction)
		defaultAllow := strings.EqualFold(defaultAction, "Allow")
		implicitOpenACL := publicEnabled && defaultAction == ""

		if publicEnabled && (defaultAllow || implicitOpenACL) && !truth.PrivateEndpointEnabled {
			expected["keyvault-public-network-open-"+truth.ID] = struct{}{}
		}
		if publicEnabled && !defaultAllow && !implicitOpenACL && !truth.PrivateEndpointEnabled {
			expected["keyvault-public-network-enabled-"+truth.ID] = struct{}{}
		}
		if publicEnabled && truth.PrivateEndpointEnabled {
			expected["keyvault-public-network-with-private-endpoint-"+truth.ID] = struct{}{}
		}
	}

	return expected
}
