package lab

import (
	"fmt"
	"strings"
)

func findEnvVarRow(payload map[string]any, assetID, settingName string) map[string]any {
	rows, _ := payload["env_vars"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		rowSettingName, _ := rowMap["setting_name"].(string)
		if normalizeResourceID(rowAssetID) == normalizeResourceID(assetID) &&
			strings.EqualFold(strings.TrimSpace(rowSettingName), strings.TrimSpace(settingName)) {
			return rowMap
		}
	}
	return nil
}

func envVarRowsForAsset(payload map[string]any, assetID string) []map[string]any {
	rows, _ := payload["env_vars"].([]any)
	matches := []map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		if normalizeResourceID(rowAssetID) == normalizeResourceID(assetID) {
			matches = append(matches, rowMap)
		}
	}
	return matches
}

func envVarRowIdentityIDs(row map[string]any) []string {
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

func envVarFindingByID(payload map[string]any, id string) map[string]any {
	findings, _ := payload["findings"].([]any)
	for _, finding := range findings {
		findingMap, ok := finding.(map[string]any)
		if !ok {
			continue
		}
		findingID, _ := findingMap["id"].(string)
		if findingID == id {
			return findingMap
		}
	}
	return nil
}

func envVarIssue(payload map[string]any, kind, scope string) map[string]any {
	issues, _ := payload["issues"].([]any)
	for _, issue := range issues {
		issueMap, ok := issue.(map[string]any)
		if !ok {
			continue
		}
		issueKind, _ := issueMap["kind"].(string)
		issueScope, _ := issueMap["scope"].(string)
		if strings.TrimSpace(issueKind) == strings.TrimSpace(kind) &&
			strings.TrimSpace(issueScope) == strings.TrimSpace(scope) {
			return issueMap
		}
	}
	return nil
}

func normalizeLocationValue(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "", "-", "", "_", "")
	return replacer.Replace(normalized)
}

func envVarIssueScope(asset liveEnvVarAssetTruth) string {
	return fmt.Sprintf("env_vars[%s/%s]", asset.ResourceGroup, asset.AssetName)
}

func validateEnvVarsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveEnvVarsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "env-vars" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-env-vars-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live env-vars context artifact",
			"lab runner env-vars context capture",
			"env-vars validation should compare the tool payload against recorded Azure app-settings truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, asset := range context.Assets {
		expectedRows := 0
		for _, truth := range context.EnvVars {
			if normalizeResourceID(truth.AssetID) == normalizeResourceID(asset.AssetID) {
				expectedRows++
			}
		}
		observedRows := envVarRowsForAsset(payload, asset.AssetID)
		if expectedRows == 0 && len(observedRows) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-rows-for-empty-asset", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars rows for Azure asset %q, but the current Azure settings read shows no visible app settings on that workload", label, asset.AssetID),
				"env-vars empty-workload visibility or Azure-backed validation context",
				"env-vars should not invent app-setting rows for a visible workload when the current Azure settings read returns none",
			))
		}
		if !asset.SettingsReadable {
			if len(observedRows) > 0 {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-rows-for-unreadable-asset", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced env-vars rows for asset %q even though the current Azure settings read was authorization-blocked for that workload", label, asset.AssetID),
					"env-vars reduced-view visibility or Azure-backed validation context",
					"env-vars should not surface app-setting rows for a workload when the reduced viewpoint cannot read that workload's app settings",
				))
			}
			if envVarIssue(payload, "collection_error", envVarIssueScope(asset)) == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-collection-error", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s did not record the expected collection_error issue for unreadable env-vars asset %q", label, asset.AssetID),
					"env-vars reduced-view error reporting or Azure-backed validation context",
					"env-vars should keep authorization-blocked app-settings reads visible through collection_error issues when reduced viewpoints cannot read a workload's settings",
				))
			}
			continue
		}
	}

	for _, truth := range context.EnvVars {
		row := findEnvVarRow(payload, truth.AssetID, truth.SettingName)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-row-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface Azure-visible env-vars row %q on asset %q", label, truth.SettingName, truth.AssetID),
				"env-vars row visibility or Azure-backed validation context",
				"env-vars should keep visible Azure app-setting rows visible when the current viewpoint can read them",
			))
			continue
		}

		rowAssetKind, _ := row["asset_kind"].(string)
		if normalizeAssetKind(rowAssetKind) != normalizeAssetKind(truth.AssetKind) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q as asset_kind %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowAssetKind, truth.AssetKind),
				"env-vars asset typing or Azure-backed validation context",
				"env-vars should keep workload asset kind aligned with the Azure workload it is summarizing",
			))
		}

		rowAssetName, _ := row["asset_name"].(string)
		if strings.TrimSpace(rowAssetName) != strings.TrimSpace(truth.AssetName) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q as asset_name %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowAssetName, truth.AssetName),
				"env-vars asset naming or Azure-backed validation context",
				"env-vars should keep workload asset names aligned with the Azure workload they summarize",
			))
		}

		rowLocation, _ := row["location"].(string)
		if normalizeLocationValue(rowLocation) != normalizeLocationValue(truth.Location) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-location-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with location %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowLocation, truth.Location),
				"env-vars location rendering or Azure-backed validation context",
				"env-vars should keep workload location aligned with the Azure workload it is summarizing",
			))
		}

		rowResourceGroup, _ := row["resource_group"].(string)
		if !strings.EqualFold(strings.TrimSpace(rowResourceGroup), strings.TrimSpace(truth.ResourceGroup)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-resource-group-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with resource_group %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowResourceGroup, truth.ResourceGroup),
				"env-vars resource-group rendering or Azure-backed validation context",
				"env-vars should keep workload resource group aligned with the Azure workload it is summarizing",
			))
		}

		rowValueType, _ := row["value_type"].(string)
		if strings.TrimSpace(rowValueType) != strings.TrimSpace(truth.ValueType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-value-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with value_type %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowValueType, truth.ValueType),
				"env-vars value classification or Azure-backed validation context",
				"env-vars should keep value_type aligned with the Azure-visible setting form it is summarizing",
			))
		}

		rowLooksSensitive, rowLooksSensitiveOK := row["looks_sensitive"].(bool)
		if !rowLooksSensitiveOK || rowLooksSensitive != truth.LooksSensitive {
			observed := "<missing>"
			if rowLooksSensitiveOK {
				observed = fmt.Sprintf("%v", rowLooksSensitive)
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-looks-sensitive-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with looks_sensitive %s, but Azure-backed classification reports %v", label, truth.SettingName, truth.AssetID, observed, truth.LooksSensitive),
				"env-vars sensitive-name classification or Azure-backed validation context",
				"env-vars should keep the sensitive-looking setting classification aligned with the current setting-name heuristic",
			))
		}

		rowReferenceTarget, _ := row["reference_target"].(string)
		expectedReferenceTarget := ""
		if truth.ReferenceTarget != nil {
			expectedReferenceTarget = *truth.ReferenceTarget
		}
		if strings.TrimSpace(rowReferenceTarget) != strings.TrimSpace(expectedReferenceTarget) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-reference-target-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with reference_target %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowReferenceTarget, expectedReferenceTarget),
				"env-vars Key Vault reference rendering or Azure-backed validation context",
				"env-vars should keep Key Vault reference targets aligned with the Azure-visible app-setting reference",
			))
		}

		if truth.ValueType == "keyvault-ref" {
			rowKVIdentity, _ := row["key_vault_reference_identity"].(string)
			expectedKVIdentity := ""
			if truth.KeyVaultReferenceIdentity != nil {
				expectedKVIdentity = *truth.KeyVaultReferenceIdentity
			}
			if strings.TrimSpace(rowKVIdentity) != strings.TrimSpace(expectedKVIdentity) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-keyvault-identity-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
					fmt.Sprintf("%s surfaced env-vars row %q on asset %q with key_vault_reference_identity %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowKVIdentity, expectedKVIdentity),
					"env-vars Key Vault identity rendering or Azure-backed validation context",
					"env-vars should keep key_vault_reference_identity aligned with the Azure workload configuration it is summarizing",
				))
			}
		}

		rowWorkloadIdentityType, _ := row["workload_identity_type"].(string)
		expectedIdentityType := ""
		if truth.WorkloadIdentityType != nil {
			expectedIdentityType = *truth.WorkloadIdentityType
		}
		if normalizeIdentityType(rowWorkloadIdentityType) != normalizeIdentityType(expectedIdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-workload-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with workload_identity_type %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowWorkloadIdentityType, expectedIdentityType),
				"env-vars workload identity typing or Azure-backed validation context",
				"env-vars should keep workload_identity_type aligned with the Azure workload identity configuration it is summarizing",
			))
		}

		rowPrincipalID, _ := row["workload_principal_id"].(string)
		expectedPrincipalID := ""
		if truth.WorkloadPrincipalID != nil {
			expectedPrincipalID = *truth.WorkloadPrincipalID
		}
		if strings.TrimSpace(rowPrincipalID) != strings.TrimSpace(expectedPrincipalID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-workload-principal-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with workload_principal_id %q, but Azure reports %q", label, truth.SettingName, truth.AssetID, rowPrincipalID, expectedPrincipalID),
				"env-vars workload principal rendering or Azure-backed validation context",
				"env-vars should keep workload_principal_id aligned with the Azure workload identity configuration it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.WorkloadIdentityIDs)
		observedIdentityIDs := normalizeStringSet(envVarRowIdentityIDs(row))
		missingIdentityIDs := []string{}
		for _, expectedIdentityID := range truth.WorkloadIdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
				missingIdentityIDs = append(missingIdentityIDs, expectedIdentityID)
			}
		}
		if len(expectedIdentityIDs) == 0 && len(observedIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-identity-ids", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced env-vars row %q on asset %q with workload_identity_ids, but Azure does not currently show user-assigned identities on that workload", label, truth.SettingName, truth.AssetID),
				"env-vars workload identity rendering or Azure-backed validation context",
				"env-vars should not invent user-assigned workload identity IDs when Azure shows none on that workload",
			))
		} else if len(missingIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-workload-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s lost Azure-visible workload_identity_ids for env-vars row %q on asset %q: %s", label, truth.SettingName, truth.AssetID, strings.Join(missingIdentityIDs, ", ")),
				"env-vars workload identity rendering or Azure-backed validation context",
				"env-vars should preserve visible user-assigned workload identity IDs when Azure shows them on the workload",
			))
		}

		expectedFindingIDs := []string{}
		if truth.LooksSensitive && truth.ValueType == "plain-text" {
			expectedFindingIDs = append(expectedFindingIDs, "env-var-plain-sensitive-"+truth.AssetID+"-"+truth.SettingName)
		}
		if truth.ValueType == "keyvault-ref" {
			expectedFindingIDs = append(expectedFindingIDs, "env-var-keyvault-ref-"+truth.AssetID+"-"+truth.SettingName)
		}
		for _, expectedFindingID := range expectedFindingIDs {
			if envVarFindingByID(payload, expectedFindingID) == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s did not emit expected env-vars finding %q for asset %q setting %q", label, expectedFindingID, truth.AssetID, truth.SettingName),
					"env-vars finding derivation or Azure-backed validation context",
					"env-vars should keep plain-text sensitive and Key Vault reference findings aligned with the visible Azure app-setting rows",
				))
			}
		}
	}

	findingsList, _ := payload["findings"].([]any)
	for _, finding := range findingsList {
		findingMap, ok := finding.(map[string]any)
		if !ok {
			continue
		}
		findingID, _ := findingMap["id"].(string)
		if strings.TrimSpace(findingID) == "" {
			continue
		}

		expected := false
		for _, truth := range context.EnvVars {
			if findingID == "env-var-plain-sensitive-"+truth.AssetID+"-"+truth.SettingName &&
				truth.LooksSensitive && truth.ValueType == "plain-text" {
				expected = true
				break
			}
			if findingID == "env-var-keyvault-ref-"+truth.AssetID+"-"+truth.SettingName &&
				truth.ValueType == "keyvault-ref" {
				expected = true
				break
			}
		}
		if !expected && (strings.HasPrefix(findingID, "env-var-plain-sensitive-") || strings.HasPrefix(findingID, "env-var-keyvault-ref-")) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted env-vars finding %q, but the current Azure app-settings read does not support that finding", label, findingID),
				"env-vars finding derivation or Azure-backed validation context",
				"env-vars should not emit plain-text sensitive or Key Vault reference findings when the current Azure app-setting rows do not justify them",
			))
		}
	}

	return findings
}
