package lab

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const crossTenantExternalSPSampleLimit = 5

type liveCrossTenantContextArtifact struct {
	ExpectedRows            []liveCrossTenantRowTruth `json:"expected_rows"`
	RequiredIssueCollectors []string                  `json:"required_issue_collectors"`
}

type liveCrossTenantRowTruth struct {
	AttackPath string   `json:"attack_path"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Priority   string   `json:"priority"`
	RelatedIDs []string `json:"related_ids,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	SignalType string   `json:"signal_type"`
	TenantID   string   `json:"tenant_id,omitempty"`
}

func captureLiveCrossTenantContext(outdir string, env []string, progressWriter io.Writer) error {
	currentContext := liveAzureContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-azure-context.json"), &currentContext); err != nil {
		return fmt.Errorf("load live azure context: %w", err)
	}

	artifact := liveCrossTenantContextArtifact{}
	authPolicies := []liveAuthPolicyTruth{}

	securityDefaults, visible, err := graphObjectByURL(
		"https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
		"az rest (cross-tenant security defaults)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if visible {
		authPolicies = append(authPolicies, authPolicySecurityDefaultsTruth(securityDefaults))
	} else {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "auth_policies.security_defaults")
	}

	authorizationPolicy, visible, err := graphObjectByURL(
		"https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
		"az rest (cross-tenant authorization policy)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if visible {
		authPolicies = append(authPolicies, authPolicyAuthorizationPolicyTruth(authorizationPolicy))
	} else {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "auth_policies.authorization_policy")
	}

	conditionalAccessPolicies, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
		"az rest (cross-tenant conditional access)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if !visible {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "auth_policies.conditional_access")
	} else {
		for _, policy := range conditionalAccessPolicies {
			authPolicies = append(authPolicies, authPolicyConditionalAccessTruth(policy))
		}
	}

	artifact.ExpectedRows = append(artifact.ExpectedRows, crossTenantPolicyRowsFromAuthPolicyTruth(authPolicies, currentContext.TenantID)...)

	servicePrincipals, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,appOwnerOrganizationId",
		"az rest (cross-tenant service principals)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if !visible {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "cross_tenant.service_principals")
	} else {
		externalServicePrincipals := []map[string]any{}
		for _, servicePrincipal := range servicePrincipals {
			ownerTenantID := strings.TrimSpace(mapStringValue(servicePrincipal, "appOwnerOrganizationId"))
			if ownerTenantID == "" || strings.EqualFold(ownerTenantID, currentContext.TenantID) {
				continue
			}
			if strings.TrimSpace(mapStringValue(servicePrincipal, "id")) == "" {
				continue
			}
			externalServicePrincipals = append(externalServicePrincipals, servicePrincipal)
		}
		sort.SliceStable(externalServicePrincipals, func(i, j int) bool {
			leftName := firstNonEmpty(mapStringValue(externalServicePrincipals[i], "displayName"), mapStringValue(externalServicePrincipals[i], "id"))
			rightName := firstNonEmpty(mapStringValue(externalServicePrincipals[j], "displayName"), mapStringValue(externalServicePrincipals[j], "id"))
			if leftName != rightName {
				return leftName < rightName
			}
			return mapStringValue(externalServicePrincipals[i], "id") < mapStringValue(externalServicePrincipals[j], "id")
		})
		for index, servicePrincipal := range externalServicePrincipals {
			if index >= crossTenantExternalSPSampleLimit {
				break
			}
			artifact.ExpectedRows = append(artifact.ExpectedRows, liveCrossTenantRowTruth{
				AttackPath: "pivot",
				ID:         mapStringValue(servicePrincipal, "id"),
				Name: firstNonEmpty(
					mapStringValue(servicePrincipal, "displayName"),
					mapStringValue(servicePrincipal, "appId"),
					mapStringValue(servicePrincipal, "id"),
					"external service principal",
				),
				Priority:   "low",
				RelatedIDs: authPolicyFilterNonEmpty(mapStringValue(servicePrincipal, "id")),
				Scope:      "tenant",
				SignalType: "external-sp",
				TenantID:   mapStringValue(servicePrincipal, "appOwnerOrganizationId"),
			})
		}
	}

	sort.Strings(artifact.RequiredIssueCollectors)
	sort.SliceStable(artifact.ExpectedRows, func(i, j int) bool {
		if artifact.ExpectedRows[i].SignalType != artifact.ExpectedRows[j].SignalType {
			return artifact.ExpectedRows[i].SignalType < artifact.ExpectedRows[j].SignalType
		}
		if artifact.ExpectedRows[i].Name != artifact.ExpectedRows[j].Name {
			return artifact.ExpectedRows[i].Name < artifact.ExpectedRows[j].Name
		}
		return artifact.ExpectedRows[i].ID < artifact.ExpectedRows[j].ID
	})

	if err := WriteJSON(filepath.Join(outdir, "live-cross-tenant-context.json"), artifact); err != nil {
		return fmt.Errorf("write live cross-tenant context artifact: %w", err)
	}
	return nil
}

func crossTenantPolicyRowsFromAuthPolicyTruth(policies []liveAuthPolicyTruth, tenantID string) []liveCrossTenantRowTruth {
	rows := []liveCrossTenantRowTruth{}
	for _, policy := range policies {
		if policy.PolicyType != "authorization-policy" {
			continue
		}

		controls := normalizeLowerStringSet(policy.Controls)
		guestInvites := ""
		for _, control := range policy.Controls {
			normalized := strings.ToLower(strings.TrimSpace(control))
			if strings.HasPrefix(normalized, "guest-invites:") {
				guestInvites = strings.TrimPrefix(normalized, "guest-invites:")
				break
			}
		}
		_, usersCanRegisterApps := controls["users-can-register-apps"]
		_, userConsent := controls["user-consent:self-service"]
		if guestInvites == "" && !usersCanRegisterApps && !userConsent {
			continue
		}

		priority := "low"
		switch {
		case guestInvites == "everyone":
			priority = "high"
		case usersCanRegisterApps || userConsent:
			priority = "medium"
		}

		rowID := firstNonEmpty(firstNonEmptyString(policy.RelatedIDs...), policy.Name)
		rows = append(rows, liveCrossTenantRowTruth{
			AttackPath: "entry",
			ID:         rowID,
			Name:       firstNonEmpty(policy.Name, "Authorization Policy"),
			Priority:   priority,
			RelatedIDs: append([]string{}, policy.RelatedIDs...),
			Scope:      "tenant",
			SignalType: "policy",
			TenantID:   tenantID,
		})
	}
	return rows
}
