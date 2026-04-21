package lab

import (
	"fmt"
	"strings"
)

func findTokensCredentialSurfaceRow(payload map[string]any, assetID, surfaceType, accessPath, operatorSignal string) map[string]any {
	rows, _ := payload["surfaces"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		rowSurfaceType, _ := rowMap["surface"].(string)
		rowAccessPath, _ := rowMap["access_path"].(string)
		rowOperatorSignal, _ := rowMap["operator_signal"].(string)
		if normalizeResourceID(rowAssetID) != normalizeResourceID(assetID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rowSurfaceType), strings.TrimSpace(surfaceType)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rowAccessPath), strings.TrimSpace(accessPath)) {
			continue
		}
		if strings.TrimSpace(rowOperatorSignal) != strings.TrimSpace(operatorSignal) {
			continue
		}
		return rowMap
	}
	return nil
}

func tokensCredentialRowsForAssetAndAccessPath(payload map[string]any, assetID, accessPath string) []map[string]any {
	rows, _ := payload["surfaces"].([]any)
	matches := []map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		rowAccessPath, _ := rowMap["access_path"].(string)
		if normalizeResourceID(rowAssetID) != normalizeResourceID(assetID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rowAccessPath), strings.TrimSpace(accessPath)) {
			continue
		}
		matches = append(matches, rowMap)
	}
	return matches
}

func validateTokensCredentialsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveTokensCredentialsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "tokens-credentials" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-tokens-credentials-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live tokens-credentials context artifact",
			"lab runner tokens-credentials context capture",
			"tokens-credentials validation should compare the tool payload against recorded Azure-backed token and credential clue truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, blocked := range context.BlockedAppSettingRead {
		rows := tokensCredentialRowsForAssetAndAccessPath(payload, blocked.AssetID, "app-setting")
		if len(rows) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-blocked-app-setting-rows", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced app-setting token or credential rows for asset %q even though the current Azure app-settings read is authorization-blocked", label, blocked.AssetName),
				"tokens-credentials reduced-view app-setting visibility or Azure-backed validation context",
				"tokens-credentials should not invent app-setting credential rows when the current viewpoint cannot read that workload's app settings",
			))
		}
		if envVarIssue(payload, "collection_error", blocked.Scope) == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-blocked-app-setting-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not record the expected collection_error issue for blocked app-setting asset %q", label, blocked.AssetName),
				"tokens-credentials reduced-view error reporting or Azure-backed validation context",
				"tokens-credentials should keep blocked env-vars collection visible through collection_error issues when reduced viewpoints cannot read app settings",
			))
		}
	}

	for _, truth := range context.ExpectedSurfaces {
		row := findTokensCredentialSurfaceRow(payload, truth.AssetID, truth.SurfaceType, truth.AccessPath, truth.OperatorSignal)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-surface", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the expected %s row for asset %q", label, truth.SurfaceType, truth.AssetName),
				"tokens-credentials row derivation or Azure-backed validation context",
				"tokens-credentials should preserve the token or credential clue rows that are derivable from the visible Azure-backed source surfaces",
			))
			continue
		}

		rowAssetKind, _ := row["kind"].(string)
		if normalizeAssetKind(rowAssetKind) != normalizeAssetKind(truth.AssetKind) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced %s for asset %q as kind %q, but the Azure-backed derivation reports %q", label, truth.SurfaceType, truth.AssetName, rowAssetKind, truth.AssetKind),
				"tokens-credentials asset typing or Azure-backed validation context",
				"tokens-credentials should keep asset kinds aligned with the workload or deployment source it is summarizing",
			))
		}

		rowAssetName, _ := row["asset"].(string)
		if strings.TrimSpace(rowAssetName) != strings.TrimSpace(truth.AssetName) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced %s for asset id %q as asset %q, but the Azure-backed derivation reports %q", label, truth.SurfaceType, truth.AssetID, rowAssetName, truth.AssetName),
				"tokens-credentials asset naming or Azure-backed validation context",
				"tokens-credentials should keep asset names aligned with the workload or deployment source it is summarizing",
			))
		}

		rowPriority, _ := row["priority"].(string)
		if strings.TrimSpace(rowPriority) != strings.TrimSpace(truth.Priority) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-priority-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced %s for asset %q with priority %q, but the Azure-backed derivation reports %q", label, truth.SurfaceType, truth.AssetName, rowPriority, truth.Priority),
				"tokens-credentials priority derivation or Azure-backed validation context",
				"tokens-credentials should keep priority aligned with the current visible token or credential clue path",
			))
		}
	}

	return findings
}
