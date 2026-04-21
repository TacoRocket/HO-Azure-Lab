package lab

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type liveAuthPoliciesContextArtifact struct {
	VisiblePolicies         []liveAuthPolicyTruth `json:"visible_policies"`
	RequiredIssueCollectors []string              `json:"required_issue_collectors"`
}

type liveAuthPolicyTruth struct {
	Controls   []string `json:"controls"`
	Name       string   `json:"name"`
	PolicyType string   `json:"policy_type"`
	RelatedIDs []string `json:"related_ids"`
	Scope      string   `json:"scope,omitempty"`
	State      string   `json:"state"`
}

func captureLiveAuthPoliciesContext(outdir string, env []string, progressWriter io.Writer) error {
	artifact := liveAuthPoliciesContextArtifact{}

	securityDefaults, visible, err := graphObjectByURL(
		"https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
		"az rest (auth-policies security defaults)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if visible {
		artifact.VisiblePolicies = append(artifact.VisiblePolicies, authPolicySecurityDefaultsTruth(securityDefaults))
	} else {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "auth_policies.security_defaults")
	}

	authorizationPolicy, visible, err := graphObjectByURL(
		"https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
		"az rest (auth-policies authorization policy)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if visible {
		artifact.VisiblePolicies = append(artifact.VisiblePolicies, authPolicyAuthorizationPolicyTruth(authorizationPolicy))
	} else {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "auth_policies.authorization_policy")
	}

	conditionalAccessPolicies, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
		"az rest (auth-policies conditional access)",
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
			artifact.VisiblePolicies = append(artifact.VisiblePolicies, authPolicyConditionalAccessTruth(policy))
		}
	}

	sort.Strings(artifact.RequiredIssueCollectors)
	sort.SliceStable(artifact.VisiblePolicies, func(i, j int) bool {
		left := artifact.VisiblePolicies[i]
		right := artifact.VisiblePolicies[j]
		if left.PolicyType != right.PolicyType {
			return left.PolicyType < right.PolicyType
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return strings.Join(left.RelatedIDs, ",") < strings.Join(right.RelatedIDs, ",")
	})

	if err := WriteJSON(filepath.Join(outdir, "live-auth-policies-context.json"), artifact); err != nil {
		return fmt.Errorf("write live auth-policies context artifact: %w", err)
	}
	return nil
}

func authPolicySecurityDefaultsTruth(policy map[string]any) liveAuthPolicyTruth {
	controls := []string{}
	state := "disabled"
	if boolValue(policy["isEnabled"]) {
		controls = []string{"baseline-mfa", "legacy-auth-protection"}
		state = "enabled"
	}
	return liveAuthPolicyTruth{
		Controls:   controls,
		Name:       firstNonEmpty(mapStringValue(policy, "displayName"), "Security Defaults"),
		PolicyType: "security-defaults",
		RelatedIDs: authPolicyFilterNonEmpty(mapStringValue(policy, "id")),
		Scope:      "tenant",
		State:      state,
	}
}

func authPolicyAuthorizationPolicyTruth(policy map[string]any) liveAuthPolicyTruth {
	controls := []string{}

	inviteSetting := mapStringValue(policy, "allowInvitesFrom")
	if inviteSetting != "" {
		controls = append(controls, "guest-invites:"+inviteSetting)
	}
	if boolValue(policy["allowUserConsentForRiskyApps"]) {
		controls = append(controls, "risky-app-consent:enabled")
	}
	if boolValue(policy["allowedToUseSSPR"]) {
		controls = append(controls, "sspr:enabled")
	}
	if boolValue(policy["blockMsolPowerShell"]) {
		controls = append(controls, "legacy-msol-powershell:blocked")
	}

	defaultPermissions := mapObjectValue(policy, "defaultUserRolePermissions")
	if boolValue(defaultPermissions["allowedToCreateApps"]) {
		controls = append(controls, "users-can-register-apps")
	}
	if boolValue(defaultPermissions["allowedToCreateSecurityGroups"]) {
		controls = append(controls, "users-can-create-security-groups")
	}
	if len(listAnyValue(defaultPermissions, "permissionGrantPoliciesAssigned")) > 0 {
		controls = append(controls, "user-consent:self-service")
	}

	return liveAuthPolicyTruth{
		Controls:   controls,
		Name:       firstNonEmpty(mapStringValue(policy, "displayName"), "Authorization Policy"),
		PolicyType: "authorization-policy",
		RelatedIDs: authPolicyFilterNonEmpty(mapStringValue(policy, "id")),
		Scope:      "tenant",
		State:      "configured",
	}
}

func authPolicyConditionalAccessTruth(policy map[string]any) liveAuthPolicyTruth {
	grantControls := authPolicyStringList(mapObjectValue(mapObjectValue(policy, "grantControls"), "builtInControls"))
	sessionControls := []string{}
	for key, value := range mapObjectValue(policy, "sessionControls") {
		switch typed := value.(type) {
		case nil:
		case bool:
			if typed {
				sessionControls = append(sessionControls, key)
			}
		case []any:
			if len(typed) > 0 {
				sessionControls = append(sessionControls, key)
			}
		case map[string]any:
			if len(typed) > 0 {
				sessionControls = append(sessionControls, key)
			}
		default:
			sessionControls = append(sessionControls, key)
		}
	}
	sort.Strings(sessionControls)

	authStrength := mapStringValue(mapObjectValue(mapObjectValue(policy, "grantControls"), "authenticationStrength"), "displayName")
	if authStrength != "" {
		grantControls = append(grantControls, "authentication-strength:"+authStrength)
	}

	users := mapObjectValue(mapObjectValue(policy, "conditions"), "users")
	applications := mapObjectValue(mapObjectValue(policy, "conditions"), "applications")
	scopeParts := []string{}
	if authPolicyContainsString(authPolicyStringList(users["includeUsers"]), "All") {
		scopeParts = append(scopeParts, "users:all")
	}
	if roles := authPolicyStringList(users["includeRoles"]); len(roles) > 0 {
		scopeParts = append(scopeParts, "roles:"+strconv.Itoa(len(roles)))
	}
	if authPolicyContainsString(authPolicyStringList(applications["includeApplications"]), "All") {
		scopeParts = append(scopeParts, "apps:all")
	} else if apps := authPolicyStringList(applications["includeApplications"]); len(apps) > 0 {
		scopeParts = append(scopeParts, "apps:"+strconv.Itoa(len(apps)))
	}

	scope := "scoped"
	if len(scopeParts) > 0 {
		scope = strings.Join(scopeParts, ", ")
	}

	return liveAuthPolicyTruth{
		Controls:   append(grantControls, sessionControls...),
		Name:       firstNonEmpty(mapStringValue(policy, "displayName"), mapStringValue(policy, "id"), "Conditional Access"),
		PolicyType: "conditional-access",
		RelatedIDs: authPolicyFilterNonEmpty(mapStringValue(policy, "id")),
		Scope:      scope,
		State:      firstNonEmpty(mapStringValue(policy, "state"), "unknown"),
	}
}

func authPolicyStringList(input any) []string {
	values, _ := input.([]any)
	items := []string{}
	for _, value := range values {
		item := strings.TrimSpace(stringValue(value))
		if item == "" {
			continue
		}
		items = append(items, item)
	}
	return items
}

func authPolicyContainsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func authPolicyFilterNonEmpty(values ...string) []string {
	filtered := []string{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}
