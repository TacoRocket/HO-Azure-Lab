package lab

import (
	"fmt"
	"strings"
)

func findPrincipalRow(payload map[string]any, principalID string) map[string]any {
	rows, _ := payload["principals"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if rowID, _ := rowMap["id"].(string); rowID == principalID {
			return rowMap
		}
	}
	return nil
}

func findPermissionRow(payload map[string]any, principalID string) map[string]any {
	rows, _ := payload["permissions"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		if rowID, _ := rowMap["principal_id"].(string); rowID == principalID {
			return rowMap
		}
	}
	return nil
}

func findPrivescCurrentIdentityPath(payload map[string]any) map[string]any {
	rows, _ := payload["paths"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		currentIdentity, _ := rowMap["current_identity"].(bool)
		pathType, _ := rowMap["path_type"].(string)
		if currentIdentity && pathType == "current-foothold-direct-control" {
			return rowMap
		}
	}
	return nil
}

func validateWhoAmIPrincipalConsistency(viewpoint string, whoamiPayload, principalsPayload map[string]any) []Finding {
	if whoamiPayload == nil || principalsPayload == nil {
		return nil
	}

	principal, _ := whoamiPayload["principal"].(map[string]any)
	principalID, _ := principal["id"].(string)
	if strings.TrimSpace(principalID) == "" {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-missing-principal-id", viewpoint),
			fmt.Sprintf("commands whoami (%s) did not report principal.id, so the validator cannot compare it to principals output", viewpoint),
			"whoami current principal rendering",
			"whoami should identify the current principal clearly enough for cross-command consistency checks",
		)}
	}

	principalRow := findPrincipalRow(principalsPayload, principalID)
	if principalRow == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-principal-not-visible-in-principals", viewpoint),
			fmt.Sprintf("commands whoami (%s) identified principal.id %q, but commands principals (%s) did not surface that same principal", viewpoint, principalID, viewpoint),
			"principals current principal visibility or whoami current principal rendering",
			"whoami and principals should stay consistent about the current principal when both commands succeed for the same viewpoint",
		)}
	}

	whoamiTypeRaw, _ := principal["principal_type"].(string)
	principalsTypeRaw, _ := principalRow["principal_type"].(string)
	whoamiType := normalizePrincipalType(whoamiTypeRaw)
	principalsType := normalizePrincipalType(principalsTypeRaw)
	findings := []Finding{}
	if whoamiType != "" && principalsType != "" && whoamiType != principalsType {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-principal-type-drift", viewpoint),
			fmt.Sprintf("commands whoami (%s) reports principal_type %q, but commands principals (%s) reports %q for the same principal.id %q", viewpoint, whoamiTypeRaw, viewpoint, principalsTypeRaw, principalID),
			"whoami and principals principal typing for the current principal",
			"whoami and principals should classify the same principal consistently when both commands succeed for the same viewpoint",
		))
	}

	if isCurrentIdentity, ok := principalRow["is_current_identity"].(bool); !ok || !isCurrentIdentity {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-principals-current-identity-drift", viewpoint),
			fmt.Sprintf("commands principals (%s) surfaced principal.id %q but did not keep it marked as the current identity", viewpoint, principalID),
			"principals current identity marking",
			"principals should keep the same principal marked as current when whoami identifies it as the active Azure session",
		))
	}

	return findings
}

func validateWhoAmIPermissionsConsistency(viewpoint string, whoamiPayload, permissionsPayload map[string]any) []Finding {
	if whoamiPayload == nil || permissionsPayload == nil {
		return nil
	}

	principal, _ := whoamiPayload["principal"].(map[string]any)
	principalID, _ := principal["id"].(string)
	if strings.TrimSpace(principalID) == "" {
		return nil
	}

	permissionRow := findPermissionRow(permissionsPayload, principalID)
	if permissionRow == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-principal-not-visible-in-permissions", viewpoint),
			fmt.Sprintf("commands whoami (%s) identified principal.id %q, but commands permissions (%s) did not surface that same principal", viewpoint, principalID, viewpoint),
			"permissions current principal visibility or whoami current principal rendering",
			"whoami and permissions should stay consistent about the current principal when both commands succeed for the same viewpoint",
		)}
	}

	whoamiTypeRaw, _ := principal["principal_type"].(string)
	permissionsTypeRaw, _ := permissionRow["principal_type"].(string)
	whoamiType := normalizePrincipalType(whoamiTypeRaw)
	permissionsType := normalizePrincipalType(permissionsTypeRaw)
	findings := []Finding{}
	if whoamiType != "" && permissionsType != "" && whoamiType != permissionsType {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-permissions-principal-type-drift", viewpoint),
			fmt.Sprintf("commands whoami (%s) reports principal_type %q, but commands permissions (%s) reports %q for the same principal.id %q", viewpoint, whoamiTypeRaw, viewpoint, permissionsTypeRaw, principalID),
			"whoami and permissions principal typing for the current principal",
			"whoami and permissions should classify the same principal consistently when both commands succeed for the same viewpoint",
		))
	}

	if isCurrentIdentity, ok := permissionRow["is_current_identity"].(bool); ok && !isCurrentIdentity {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-permissions-current-identity-drift", viewpoint),
			fmt.Sprintf("commands permissions (%s) surfaced principal.id %q but did not keep it marked as the current identity", viewpoint, principalID),
			"permissions current identity marking",
			"permissions should keep the same principal marked as current when whoami identifies it as the active Azure session",
		))
	}

	return findings
}

func validateWhoAmIRbacConsistency(viewpoint string, whoamiPayload, rbacPayload map[string]any) []Finding {
	if whoamiPayload == nil || rbacPayload == nil {
		return nil
	}

	principal, _ := whoamiPayload["principal"].(map[string]any)
	principalID, _ := principal["id"].(string)
	if strings.TrimSpace(principalID) == "" {
		return nil
	}

	findings := []Finding{}
	principalRow := findPrincipalRow(rbacPayload, principalID)
	if principalRow == nil {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-principal-not-visible-in-rbac-principals", viewpoint),
			fmt.Sprintf("commands whoami (%s) identified principal.id %q, but commands rbac (%s) did not keep that principal visible in its principals list", viewpoint, principalID, viewpoint),
			"rbac principal visibility or whoami current principal rendering",
			"whoami and rbac should stay consistent about the current principal when both commands succeed for the same viewpoint",
		))
		return findings
	}

	whoamiTypeRaw, _ := principal["principal_type"].(string)
	rbacTypeRaw, _ := principalRow["principal_type"].(string)
	whoamiType := normalizePrincipalType(whoamiTypeRaw)
	rbacType := normalizePrincipalType(rbacTypeRaw)
	if whoamiType != "" && rbacType != "" && whoamiType != rbacType {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-rbac-principal-type-drift", viewpoint),
			fmt.Sprintf("commands whoami (%s) reports principal_type %q, but commands rbac (%s) reports %q for the same principal.id %q", viewpoint, whoamiTypeRaw, viewpoint, rbacTypeRaw, principalID),
			"whoami and rbac principal typing for the current principal",
			"whoami and rbac should classify the same principal consistently when both commands succeed for the same viewpoint",
		))
	}

	return findings
}

func validateWhoAmIPrivescConsistency(viewpoint string, whoamiPayload, permissionsPayload, privescPayload map[string]any) []Finding {
	if whoamiPayload == nil || privescPayload == nil {
		return nil
	}

	principal, _ := whoamiPayload["principal"].(map[string]any)
	principalID, _ := principal["id"].(string)
	if strings.TrimSpace(principalID) == "" {
		return nil
	}

	findings := []Finding{}
	permissionRow := findPermissionRow(permissionsPayload, principalID)
	currentPath := findPrivescCurrentIdentityPath(privescPayload)
	if currentPath == nil {
		if permissionRow != nil {
			if privileged, ok := permissionRow["privileged"].(bool); ok && privileged {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("commands-whoami-%s-privesc-current-identity-path-missing", viewpoint),
					fmt.Sprintf("commands permissions (%s) marks principal.id %q as privileged, but commands privesc (%s) did not return a current-foothold-direct-control path", viewpoint, principalID, viewpoint),
					"privesc current identity path visibility or permissions/privesc consistency",
					"privesc should keep the current direct-control foothold visible when permissions already shows the current principal as privileged",
				))
			}
		}
		return findings
	}

	pathPrincipalID, _ := currentPath["principal_id"].(string)
	if permissionRow != nil {
		if privileged, ok := permissionRow["privileged"].(bool); ok && !privileged && pathPrincipalID == principalID {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("commands-whoami-%s-privesc-non-privileged-current-path", viewpoint),
				fmt.Sprintf("commands permissions (%s) marks principal.id %q as not privileged, but commands privesc (%s) still returned a current-foothold-direct-control path for that same principal", viewpoint, principalID, viewpoint),
				"privesc current identity path visibility or permissions/privesc consistency",
				"privesc should not invent a current direct-control foothold when permissions does not show the current principal as privileged",
			))
		}
	}
	if pathPrincipalID != principalID {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-privesc-principal-id-drift", viewpoint),
			fmt.Sprintf("commands whoami (%s) identified principal.id %q, but commands privesc (%s) rooted its current-foothold-direct-control path in %q", viewpoint, principalID, viewpoint, pathPrincipalID),
			"privesc current identity anchoring",
			"privesc should root the current direct-control path in the same principal identified by whoami",
		))
	}

	whoamiTypeRaw, _ := principal["principal_type"].(string)
	privescTypeRaw, _ := currentPath["principal_type"].(string)
	whoamiType := normalizePrincipalType(whoamiTypeRaw)
	privescType := normalizePrincipalType(privescTypeRaw)
	if whoamiType != "" && privescType != "" && whoamiType != privescType {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("commands-whoami-%s-privesc-principal-type-drift", viewpoint),
			fmt.Sprintf("commands whoami (%s) reports principal_type %q, but commands privesc (%s) reports %q for the current-foothold-direct-control path", viewpoint, whoamiTypeRaw, viewpoint, privescTypeRaw),
			"whoami and privesc principal typing for the current foothold",
			"whoami and privesc should classify the same current foothold consistently when both commands succeed for the same viewpoint",
		))
	}

	return findings
}
