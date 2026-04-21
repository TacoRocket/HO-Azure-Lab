package lab

import (
	"fmt"
	"strings"
)

func findAppCredentialRow(payload map[string]any, rowClass, targetObjectType, targetObjectID, controlPath, credentialType string) map[string]any {
	rows, _ := payload["app_credentials"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowRowClass, _ := rowMap["row_class"].(string)
		rowTargetObjectType, _ := rowMap["target_object_type"].(string)
		rowTargetObjectID, _ := rowMap["target_object_id"].(string)
		rowControlPath, _ := rowMap["control_path"].(string)
		rowCredentialType, _ := rowMap["credential_type"].(string)
		if strings.TrimSpace(rowRowClass) != strings.TrimSpace(rowClass) {
			continue
		}
		if strings.TrimSpace(rowTargetObjectType) != strings.TrimSpace(targetObjectType) {
			continue
		}
		if strings.TrimSpace(rowControlPath) != strings.TrimSpace(controlPath) {
			continue
		}
		if strings.TrimSpace(rowCredentialType) != strings.TrimSpace(credentialType) {
			continue
		}
		if normalizeResourceID(rowTargetObjectID) == normalizeResourceID(targetObjectID) {
			return rowMap
		}
	}
	return nil
}

func validateAppCredentialsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAppCredentialsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "app-credentials" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-app-credentials-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live app-credentials context artifact",
			"lab runner app-credentials context capture",
			"app-credentials validation should compare the tool payload against recorded Entra canary truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["app_credentials"].([]any)
	if context.ExpectZeroRows {
		if len(rows) != 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-expected-empty-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced %d app-credentials rows, but the current reduced-viewpoint lab posture expects none", label, len(rows)),
				"app-credentials reduced-view visibility or Entra-backed validation context",
				"app-credentials should keep reduced viewpoints honestly empty when the current lab does not give them visible Entra credential-control paths",
			))
		}
		return findings
	}

	for _, truth := range context.OwnedApplications {
		directRow := findAppCredentialRow(payload, "directly_addable", "Application", truth.ObjectID, "application-owner", "password-or-key")
		if directRow == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-owned-application-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the owned-application credential-control row for application %q", label, truth.DisplayName),
				"app-credentials application-owner rendering or Entra-backed validation context",
				"app-credentials should surface directly addable application credential rows when the current identity owns the lab canary application",
			))
		}
		federatedControlRow := findAppCredentialRow(payload, "directly_addable_federated_trust", "Application", truth.ObjectID, "application-owner", "federated")
		if federatedControlRow == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-owned-federated-control-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the owned-application federated-trust control row for application %q", label, truth.DisplayName),
				"app-credentials federated-trust control rendering or Entra-backed validation context",
				"app-credentials should surface directly addable federated-trust rows when the current identity owns the lab canary application",
			))
		}
	}

	for _, truth := range context.OwnedServicePrincipals {
		directRow := findAppCredentialRow(payload, "directly_addable", "ServicePrincipal", truth.ObjectID, "service-principal-owner", "password-or-key")
		if directRow == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-owned-service-principal-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the owned service-principal credential-control row for service principal %q", label, truth.DisplayName),
				"app-credentials service-principal-owner rendering or Entra-backed validation context",
				"app-credentials should surface directly addable service-principal rows when the current identity owns the lab canary service principal",
			))
		}
	}

	for _, truth := range context.ExistingFederatedApplications {
		row := findAppCredentialRow(payload, "federated_trust_present", "Application", truth.ObjectID, "existing-federated-trust", "federated")
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-existing-federated-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the existing federated-trust row for application %q", label, truth.DisplayName),
				"app-credentials existing federated-trust rendering or Entra-backed validation context",
				"app-credentials should surface existing federated-trust rows when the lab canary application already has federated credentials",
			))
		}
	}

	for _, truth := range context.ExistingCredentialApplications {
		row := findAppCredentialRow(payload, "existing_credential", "Application", truth.ObjectID, "existing-auth-material", truth.CredentialType)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-existing-credential-row", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the existing %s credential row for application %q", label, truth.CredentialType, truth.DisplayName),
				"app-credentials existing-credential rendering or Entra-backed validation context",
				"app-credentials should surface existing application credential rows when the lab canary application already has visible credential metadata",
			))
		}
	}

	return findings
}
