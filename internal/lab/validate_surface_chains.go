package lab

import (
	"fmt"
	"slices"
	"strings"
)

type credentialPathExpectedTruth struct {
	AssetID          string
	AssetName        string
	AssetKind        string
	SettingName      string
	TargetService    string
	TargetResolution string
	TargetNames      []string
	TargetCount      int
	ClueType         string
	RequiredEvidence []string
}

func findCredentialPathRow(payload map[string]any, assetID, settingName, targetService string) map[string]any {
	rows, _ := payload["paths"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		rowSettingName, _ := rowMap["setting_name"].(string)
		rowTargetService, _ := rowMap["target_service"].(string)
		if normalizeResourceID(rowAssetID) != normalizeResourceID(assetID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rowSettingName), strings.TrimSpace(settingName)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rowTargetService), strings.TrimSpace(targetService)) {
			continue
		}
		return rowMap
	}
	return nil
}

func credentialPathRows(payload map[string]any) []map[string]any {
	rows, _ := payload["paths"].([]any)
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

func credentialPathRowKey(row map[string]any) string {
	assetID, _ := row["asset_id"].(string)
	settingName, _ := row["setting_name"].(string)
	targetService, _ := row["target_service"].(string)
	return normalizeResourceID(assetID) + "|" + strings.ToLower(strings.TrimSpace(settingName)) + "|" + strings.ToLower(strings.TrimSpace(targetService))
}

func credentialPathExpectedKey(truth credentialPathExpectedTruth) string {
	return normalizeResourceID(truth.AssetID) + "|" + strings.ToLower(strings.TrimSpace(truth.SettingName)) + "|" + strings.ToLower(strings.TrimSpace(truth.TargetService))
}

func payloadStringSliceValues(row map[string]any, key string) []string {
	values, _ := row[key].([]any)
	result := []string{}
	for _, value := range values {
		text, _ := value.(string)
		if strings.TrimSpace(text) == "" {
			continue
		}
		result = append(result, text)
	}
	return result
}

func credentialPathTokenSurfaceAssetIDs(context *liveTokensCredentialsContextArtifact) map[string]struct{} {
	result := map[string]struct{}{}
	if context == nil {
		return result
	}
	for _, truth := range context.ExpectedSurfaces {
		if normalizeResourceID(truth.AssetID) == "" {
			continue
		}
		result[normalizeResourceID(truth.AssetID)] = struct{}{}
	}
	return result
}

func credentialPathVaultMatch(referenceTarget string, vaults []liveKeyVaultTruth) *liveKeyVaultTruth {
	target := strings.TrimSpace(referenceTarget)
	if target == "" {
		return nil
	}
	target = strings.TrimSpace(strings.TrimPrefix(target, "https://"))
	target = strings.TrimSpace(strings.TrimPrefix(target, "http://"))
	target = strings.ToLower(target)
	for _, vault := range vaults {
		candidates := []string{
			strings.ToLower(strings.TrimSpace(vault.Name)),
			strings.ToLower(strings.TrimSpace(strings.TrimPrefix(vault.VaultURI, "https://"))),
			strings.ToLower(strings.TrimSpace(strings.TrimPrefix(vault.VaultURI, "http://"))),
		}
		for _, candidate := range candidates {
			if candidate == "" {
				continue
			}
			if strings.Contains(target, candidate) || strings.Contains(candidate, target) {
				vaultCopy := vault
				return &vaultCopy
			}
		}
	}
	return nil
}

func likelyDatabaseSetting(settingName string) bool {
	normalized := strings.ToLower(strings.TrimSpace(settingName))
	for _, token := range []string{"db", "database", "sql", "postgres", "mysql"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func likelyStorageSetting(settingName string) bool {
	normalized := strings.ToLower(strings.TrimSpace(settingName))
	for _, token := range []string{"azurewebjobsstorage", "storage", "blob", "queue", "file", "share"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func sortedVisibleDatabaseNames(context *liveDatabasesContextArtifact) []string {
	if context == nil {
		return nil
	}
	names := []string{}
	for _, truth := range context.DatabaseServers {
		if strings.TrimSpace(truth.Name) == "" {
			continue
		}
		names = append(names, truth.Name)
	}
	slices.Sort(names)
	return names
}

func sortedVisibleStorageNames(context *liveStorageContextArtifact) []string {
	if context == nil {
		return nil
	}
	names := []string{}
	for _, truth := range context.StorageAssets {
		if strings.TrimSpace(truth.Name) == "" {
			continue
		}
		names = append(names, truth.Name)
	}
	slices.Sort(names)
	return names
}

func expectedCredentialPathTruths(
	envVars *liveEnvVarsContextArtifact,
	tokens *liveTokensCredentialsContextArtifact,
	databases *liveDatabasesContextArtifact,
	keyVaults *liveKeyVaultContextArtifact,
	storage *liveStorageContextArtifact,
) []credentialPathExpectedTruth {
	if envVars == nil || tokens == nil {
		return nil
	}
	tokenAssets := credentialPathTokenSurfaceAssetIDs(tokens)
	result := []credentialPathExpectedTruth{}
	for _, truth := range envVars.EnvVars {
		if _, ok := tokenAssets[normalizeResourceID(truth.AssetID)]; !ok {
			continue
		}

		switch strings.TrimSpace(truth.ValueType) {
		case "keyvault-ref":
			if keyVaults == nil || strings.TrimSpace(firstNonEmptyString(derefString(truth.ReferenceTarget))) == "" {
				continue
			}
			vault := credentialPathVaultMatch(derefString(truth.ReferenceTarget), keyVaults.KeyVaults)
			if vault == nil {
				result = append(result, credentialPathExpectedTruth{
					AssetID:          truth.AssetID,
					AssetName:        truth.AssetName,
					AssetKind:        truth.AssetKind,
					SettingName:      truth.SettingName,
					TargetService:    "keyvault",
					TargetResolution: "named target not visible",
					TargetNames:      nil,
					TargetCount:      0,
					ClueType:         "keyvault-reference",
					RequiredEvidence: []string{"env-vars", "tokens-credentials", "keyvault"},
				})
				continue
			}
			result = append(result, credentialPathExpectedTruth{
				AssetID:          truth.AssetID,
				AssetName:        truth.AssetName,
				AssetKind:        truth.AssetKind,
				SettingName:      truth.SettingName,
				TargetService:    "keyvault",
				TargetResolution: "named match",
				TargetNames:      []string{vault.Name},
				TargetCount:      1,
				ClueType:         "keyvault-reference",
				RequiredEvidence: []string{"env-vars", "tokens-credentials", "keyvault"},
			})
		case "plain-text":
			if !truth.LooksSensitive && !likelyStorageSetting(truth.SettingName) {
				continue
			}
			if likelyDatabaseSetting(truth.SettingName) {
				targets := sortedVisibleDatabaseNames(databases)
				targetResolution := "service hint only"
				if len(targets) > 0 {
					targetResolution = "tenant-wide candidates"
				}
				result = append(result, credentialPathExpectedTruth{
					AssetID:          truth.AssetID,
					AssetName:        truth.AssetName,
					AssetKind:        truth.AssetKind,
					SettingName:      truth.SettingName,
					TargetService:    "database",
					TargetResolution: targetResolution,
					TargetNames:      targets,
					TargetCount:      len(targets),
					ClueType:         "plain-text-secret",
					RequiredEvidence: []string{"env-vars", "tokens-credentials", "databases"},
				})
			}
			if likelyStorageSetting(truth.SettingName) {
				targets := sortedVisibleStorageNames(storage)
				targetResolution := "service hint only"
				if len(targets) > 0 {
					targetResolution = "tenant-wide candidates"
				}
				result = append(result, credentialPathExpectedTruth{
					AssetID:          truth.AssetID,
					AssetName:        truth.AssetName,
					AssetKind:        truth.AssetKind,
					SettingName:      truth.SettingName,
					TargetService:    "storage",
					TargetResolution: targetResolution,
					TargetNames:      targets,
					TargetCount:      len(targets),
					ClueType:         "plain-text-secret",
					RequiredEvidence: []string{"env-vars", "tokens-credentials", "storage"},
				})
			}
		}
	}
	return result
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func validateCredentialPathPayloadAgainstAzureContext(
	entry CommandLogEntry,
	label string,
	payload map[string]any,
	envVars *liveEnvVarsContextArtifact,
	tokens *liveTokensCredentialsContextArtifact,
	databases *liveDatabasesContextArtifact,
	keyVaults *liveKeyVaultContextArtifact,
	storage *liveStorageContextArtifact,
) []Finding {
	if entry.SurfaceKind != "families" || entry.SurfaceName != "credential-path" {
		return nil
	}
	if envVars == nil || tokens == nil || databases == nil || keyVaults == nil || storage == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record the live source contexts needed for credential-path validation",
			"lab runner credential-path family context capture",
			"credential-path validation should compare the grouped family rows against the recorded env-vars, tokens-credentials, databases, keyvault, and storage truth backing the family story",
		)}
	}

	findings := []Finding{}
	expectedTruths := expectedCredentialPathTruths(envVars, tokens, databases, keyVaults, storage)
	expectedByKey := map[string]credentialPathExpectedTruth{}
	for _, truth := range expectedTruths {
		expectedByKey[credentialPathExpectedKey(truth)] = truth
	}

	rows := credentialPathRows(payload)
	if len(expectedByKey) == 0 && len(rows) > 0 {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-family-rows", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced credential-path rows even though the current recorded source-command truth does not support any grouped credential-path rows for this viewpoint", label),
			"credential-path grouped row admission or grouped-source reuse",
			"credential-path should stay empty when the current env-vars, tokens-credentials, and visible target inventories do not support a defended grouped row",
		))
		return findings
	}

	for _, truth := range expectedTruths {
		row := findCredentialPathRow(payload, truth.AssetID, truth.SettingName, truth.TargetService)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-%s-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName)), truth.TargetService),
				fmt.Sprintf("%s did not surface the expected credential-path row for asset %q setting %q toward %s", label, truth.AssetID, truth.SettingName, truth.TargetService),
				"credential-path grouped row admission or grouped-source reuse",
				"credential-path should preserve defended grouped rows when the live env-vars clue, token-capable asset surface, and visible target inventory still support them",
			))
			continue
		}

		rowAssetKind, _ := row["asset_kind"].(string)
		if normalizeAssetKind(rowAssetKind) != normalizeAssetKind(truth.AssetKind) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-asset-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
				fmt.Sprintf("%s surfaced credential-path row %q on asset %q as asset_kind %q, but the recorded source truth reports %q", label, truth.SettingName, truth.AssetID, rowAssetKind, truth.AssetKind),
				"credential-path grouped asset typing or grouped-source reuse",
				"credential-path should keep grouped asset kind aligned with the visible workload that produced the source clue",
			))
		}

		rowAssetName, _ := row["asset_name"].(string)
		if strings.TrimSpace(rowAssetName) != strings.TrimSpace(truth.AssetName) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-asset-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
				fmt.Sprintf("%s surfaced credential-path row %q on asset %q as asset_name %q, but the recorded source truth reports %q", label, truth.SettingName, truth.AssetID, rowAssetName, truth.AssetName),
				"credential-path grouped asset naming or grouped-source reuse",
				"credential-path should keep grouped asset naming aligned with the visible workload that produced the source clue",
			))
		}

		rowClueType, _ := row["clue_type"].(string)
		if strings.TrimSpace(rowClueType) != strings.TrimSpace(truth.ClueType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-clue-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
				fmt.Sprintf("%s surfaced credential-path row %q on asset %q with clue_type %q, but the backing source truth supports %q", label, truth.SettingName, truth.AssetID, rowClueType, truth.ClueType),
				"credential-path grouped clue typing or grouped-source reuse",
				"credential-path should keep grouped clue typing aligned with the visible env-vars source clue it is summarizing",
			))
		}

		rowTargetResolution, _ := row["target_resolution"].(string)
		if strings.TrimSpace(rowTargetResolution) != strings.TrimSpace(truth.TargetResolution) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-target-resolution-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
				fmt.Sprintf("%s surfaced credential-path row %q on asset %q with target_resolution %q, but the recorded source truth supports %q", label, truth.SettingName, truth.AssetID, rowTargetResolution, truth.TargetResolution),
				"credential-path grouped target narrowing or grouped-source reuse",
				"credential-path should keep target-resolution labeling aligned with whether the current source truth supports a named match or only a broader candidate set",
			))
		}

		rowTargetCount, _ := row["target_count"].(float64)
		if int(rowTargetCount) != truth.TargetCount {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-target-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
				fmt.Sprintf("%s surfaced credential-path row %q on asset %q with target_count %d, but the recorded source truth supports %d visible targets", label, truth.SettingName, truth.AssetID, int(rowTargetCount), truth.TargetCount),
				"credential-path grouped target inventory reuse",
				"credential-path should keep grouped target_count aligned with the visible target inventory it is summarizing",
			))
		}

		observedTargetNames := payloadStringSliceValues(row, "target_names")
		for _, expectedTargetName := range truth.TargetNames {
			if !slices.Contains(observedTargetNames, expectedTargetName) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-target-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
					fmt.Sprintf("%s surfaced credential-path row %q on asset %q without expected visible target %q", label, truth.SettingName, truth.AssetID, expectedTargetName),
					"credential-path grouped target naming or grouped-source reuse",
					"credential-path should keep grouped visible target names aligned with the visible target inventory it is summarizing",
				))
				break
			}
		}

		observedEvidence := payloadStringSliceValues(row, "evidence_commands")
		for _, requiredEvidence := range truth.RequiredEvidence {
			if !slices.Contains(observedEvidence, requiredEvidence) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-evidence-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(truth.SettingName))),
					fmt.Sprintf("%s surfaced credential-path row %q on asset %q without required evidence command %q", label, truth.SettingName, truth.AssetID, requiredEvidence),
					"credential-path grouped evidence-command reuse",
					"credential-path should keep the backing evidence_commands aligned with the live source-command surfaces that still defend the grouped row",
				))
				break
			}
		}
	}

	for _, row := range rows {
		key := credentialPathRowKey(row)
		if _, ok := expectedByKey[key]; ok {
			continue
		}
		assetID, _ := row["asset_id"].(string)
		settingName, _ := row["setting_name"].(string)
		targetService, _ := row["target_service"].(string)
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-%s-unexpected", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(strings.ToLower(strings.TrimSpace(settingName)), "_", "-")),
			fmt.Sprintf("%s surfaced unexpected credential-path row for asset %q setting %q toward %q that the recorded source-command truth does not currently defend", label, assetID, settingName, targetService),
			"credential-path grouped row admission or grouped-source reuse",
			"credential-path should not invent grouped rows beyond the current defended source clue plus visible target inventory story",
		))
	}

	return findings
}
