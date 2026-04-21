package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func loadSiblingCommandPayload(payloadPath, commandName, viewpoint string) (map[string]any, error) {
	payloadsRoot := filepath.Dir(payloadPath)
	for {
		if filepath.Base(payloadsRoot) == "payloads" {
			break
		}
		next := filepath.Dir(payloadsRoot)
		if next == payloadsRoot {
			return nil, fmt.Errorf("could not locate payloads root from %q", payloadPath)
		}
		payloadsRoot = next
	}
	commandPayloadPath := filepath.Join(payloadsRoot, "commands", commandName, viewpoint, "loot", commandName+".json")
	payloadData, err := os.ReadFile(commandPayloadPath)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{}
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func validateEscalationPathPayloadAgainstSourceTruth(
	entry CommandLogEntry,
	label string,
	payload map[string]any,
	permissionsPayload map[string]any,
	roleTrustsPayload map[string]any,
) []Finding {
	if entry.SurfaceKind != "families" || entry.SurfaceName != "escalation-path" {
		return nil
	}

	currentPrivileged := currentPrivilegedPermissionIDs(permissionsPayload)
	currentIdentities := currentIdentityPermissionIDs(permissionsPayload)
	trustTargets := currentFootholdTrustTargets(permissionsPayload, roleTrustsPayload)
	rows := chainPathRows(payload)

	directRows := []map[string]any{}
	trustRows := []map[string]any{}
	for _, row := range rows {
		sourceCommand, _ := row["source_command"].(string)
		switch strings.TrimSpace(sourceCommand) {
		case "permissions":
			directRows = append(directRows, row)
		case "role-trusts":
			trustRows = append(trustRows, row)
		}
	}

	findings := []Finding{}

	if len(currentPrivileged) == 0 && len(trustTargets) == 0 {
		if len(rows) == 0 {
			return nil
		}
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-rows", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced escalation-path rows even though the sibling permissions and role-trusts payloads do not show a defended current-foothold escalation lead for this viewpoint", label),
			"escalation-path grouped row admission",
			"escalation-path should stay empty when the current viewpoint does not show a privileged current foothold or a stronger trust-expansion target connected to that foothold",
		)}
	}

	if len(currentPrivileged) > 0 {
		foundDirect := false
		for _, row := range directRows {
			assetID, _ := row["asset_id"].(string)
			targetService, _ := row["target_service"].(string)
			targetResolution, _ := row["target_resolution"].(string)
			if !slicesContainsNormalized(currentPrivileged, assetID) {
				continue
			}
			if strings.TrimSpace(targetService) == "azure-control" && strings.TrimSpace(targetResolution) == "path-confirmed" {
				foundDirect = true
			}
		}
		if !foundDirect {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-direct-control", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not preserve a direct-control escalation row for the privileged current foothold visible in permissions", label),
				"escalation-path direct-control reuse",
				"escalation-path should preserve at least one current-foothold direct-control row when permissions already shows a privileged current identity",
			))
		}
	}

	for _, row := range directRows {
		assetID, _ := row["asset_id"].(string)
		if !slicesContainsNormalized(currentIdentities, assetID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-direct-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced a direct-control row for %q even though that identity is not a current foothold in permissions", label, assetID),
				"escalation-path current-foothold anchoring",
				"direct-control escalation rows should stay anchored to identities that permissions currently marks as the active foothold",
			))
			break
		}
	}

	if len(trustTargets) > 0 {
		foundTrust := false
		for _, row := range trustRows {
			assetID, _ := row["asset_id"].(string)
			if !slicesContainsNormalized(currentIdentities, assetID) {
				continue
			}
			targetIDs := payloadStringSliceValues(row, "target_ids")
			for _, targetID := range targetIDs {
				if slicesContainsNormalized(trustTargets, targetID) {
					foundTrust = true
					break
				}
			}
			if foundTrust {
				break
			}
		}
		if !foundTrust {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-trust-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not preserve a trust-expansion row for the stronger target already defended by permissions plus role-trusts", label),
				"escalation-path trust-expansion reuse",
				"escalation-path should preserve at least one current-foothold trust row when role-trusts plus permissions already show a stronger reachable target",
			))
		}
	}

	return findings
}

func currentIdentityPermissionIDs(permissionsPayload map[string]any) []string {
	rows, _ := permissionsPayload["permissions"].([]any)
	ids := []string{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		isCurrent, _ := rowMap["is_current_identity"].(bool)
		if !isCurrent {
			continue
		}
		principalID, _ := rowMap["principal_id"].(string)
		if strings.TrimSpace(principalID) != "" {
			ids = append(ids, principalID)
		}
	}
	return ids
}

func currentPrivilegedPermissionIDs(permissionsPayload map[string]any) []string {
	rows, _ := permissionsPayload["permissions"].([]any)
	ids := []string{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		isCurrent, _ := rowMap["is_current_identity"].(bool)
		privileged, _ := rowMap["privileged"].(bool)
		if !isCurrent || !privileged {
			continue
		}
		principalID, _ := rowMap["principal_id"].(string)
		if strings.TrimSpace(principalID) != "" {
			ids = append(ids, principalID)
		}
	}
	return ids
}

func privilegedPermissionIDs(permissionsPayload map[string]any) []string {
	rows, _ := permissionsPayload["permissions"].([]any)
	ids := []string{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		privileged, _ := rowMap["privileged"].(bool)
		if !privileged {
			continue
		}
		principalID, _ := rowMap["principal_id"].(string)
		if strings.TrimSpace(principalID) != "" {
			ids = append(ids, principalID)
		}
	}
	return ids
}

func currentFootholdTrustTargets(permissionsPayload map[string]any, roleTrustsPayload map[string]any) []string {
	currentIDs := currentIdentityPermissionIDs(permissionsPayload)
	permissionRowsByPrincipal := permissionRowsByPrincipalID(permissionsPayload)
	trustRows, _ := roleTrustsPayload["trusts"].([]any)
	appOwners := map[string]map[string]any{}
	targets := []string{}

	for _, row := range trustRows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		sourceObjectID, _ := rowMap["source_object_id"].(string)
		if !slicesContainsNormalized(currentIDs, sourceObjectID) {
			continue
		}
		currentPermission := lookupPermissionRow(permissionRowsByPrincipal, sourceObjectID)
		trustType, _ := rowMap["trust_type"].(string)
		targetObjectID, _ := rowMap["target_object_id"].(string)
		if strings.TrimSpace(trustType) == "app-owner" && strings.TrimSpace(targetObjectID) != "" {
			appOwners[normalizeResourceID(targetObjectID)] = currentPermission
		}
		targetPermission := lookupPermissionRow(permissionRowsByPrincipal, targetObjectID)
		if payloadPermissionAddsNetValue(currentPermission, targetPermission) {
			targets = append(targets, targetObjectID)
		}
		backingSPID, _ := rowMap["backing_service_principal_id"].(string)
		backingPermission := lookupPermissionRow(permissionRowsByPrincipal, backingSPID)
		if payloadPermissionAddsNetValue(currentPermission, backingPermission) {
			targets = append(targets, backingSPID)
		}
	}

	for _, row := range trustRows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		trustType, _ := rowMap["trust_type"].(string)
		if strings.TrimSpace(trustType) != "federated-credential" {
			continue
		}
		sourceObjectID, _ := rowMap["source_object_id"].(string)
		currentPermission, ok := appOwners[normalizeResourceID(sourceObjectID)]
		if !ok {
			continue
		}
		targetObjectID, _ := rowMap["target_object_id"].(string)
		targetPermission := lookupPermissionRow(permissionRowsByPrincipal, targetObjectID)
		if payloadPermissionAddsNetValue(currentPermission, targetPermission) {
			targets = append(targets, targetObjectID)
		}
	}

	return dedupeNormalizedIDs(targets)
}

func permissionRowsByPrincipalID(permissionsPayload map[string]any) map[string]map[string]any {
	rows, _ := permissionsPayload["permissions"].([]any)
	result := map[string]map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		principalID, _ := rowMap["principal_id"].(string)
		if strings.TrimSpace(principalID) == "" {
			continue
		}
		result[normalizeResourceID(principalID)] = rowMap
	}
	return result
}

func lookupPermissionRow(rows map[string]map[string]any, principalID string) map[string]any {
	return rows[normalizeResourceID(principalID)]
}

func payloadPermissionAddsNetValue(currentPermission map[string]any, targetPermission map[string]any) bool {
	if !payloadPermissionPrivileged(targetPermission) {
		return false
	}
	if currentPermission == nil {
		return true
	}
	if len(payloadPermissionNewScopes(currentPermission, targetPermission)) > 0 {
		return true
	}
	return payloadPermissionRoleStrength(targetPermission) > payloadPermissionRoleStrength(currentPermission)
}

func payloadPermissionPrivileged(permission map[string]any) bool {
	if permission == nil {
		return false
	}
	privileged, _ := permission["privileged"].(bool)
	return privileged
}

func payloadPermissionNewScopes(currentPermission map[string]any, targetPermission map[string]any) []string {
	targetScopes := payloadStringSliceValues(targetPermission, "scope_ids")
	if currentPermission == nil {
		return targetScopes
	}
	currentScopes := payloadStringSliceValues(currentPermission, "scope_ids")
	newScopes := []string{}
	for _, targetScope := range targetScopes {
		applies := false
		for _, currentScope := range currentScopes {
			if payloadScopeAppliesToResource(currentScope, targetScope) {
				applies = true
				break
			}
		}
		if !applies {
			newScopes = append(newScopes, targetScope)
		}
	}
	return newScopes
}

func payloadPermissionRoleStrength(permission map[string]any) int {
	if permission == nil {
		return 0
	}
	roles := payloadStringSliceValues(permission, "high_impact_roles")
	strength := 0
	for _, role := range roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "owner":
			if strength < 3 {
				strength = 3
			}
		case "contributor":
			if strength < 1 {
				strength = 1
			}
		}
	}
	return strength
}

func payloadScopeAppliesToResource(currentScopeID string, targetScopeID string) bool {
	current := strings.TrimRight(strings.TrimSpace(currentScopeID), "/")
	target := strings.TrimRight(strings.TrimSpace(targetScopeID), "/")
	if current == "" || target == "" {
		return false
	}
	return current == target || strings.HasPrefix(target, current+"/")
}

func dedupeNormalizedIDs(values []string) []string {
	seen := map[string]string{}
	result := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := normalizeResourceID(trimmed)
		if key == "" {
			key = strings.ToLower(trimmed)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = trimmed
		result = append(result, trimmed)
	}
	return result
}
