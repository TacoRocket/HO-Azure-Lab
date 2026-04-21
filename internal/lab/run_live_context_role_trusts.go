package lab

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

type liveRoleTrustsContextArtifact struct {
	ExpectZeroRows          bool                 `json:"expect_zero_rows"`
	ExpectedTrusts          []liveRoleTrustTruth `json:"expected_trusts"`
	RequiredIssueCollectors []string             `json:"required_issue_collectors"`
}

type liveRoleTrustTruth struct {
	Confidence       string   `json:"confidence"`
	ControlPrimitive string   `json:"control_primitive,omitempty"`
	EvidenceType     string   `json:"evidence_type"`
	RelatedIDs       []string `json:"related_ids,omitempty"`
	SourceObjectID   string   `json:"source_object_id"`
	SourceType       string   `json:"source_type"`
	SummaryContains  []string `json:"summary_contains,omitempty"`
	TargetObjectID   string   `json:"target_object_id"`
	TargetType       string   `json:"target_type"`
	TrustType        string   `json:"trust_type"`
}

type roleTrustCanaryManifest struct {
	APIApplicationID         string
	APIServicePrincipalID    string
	ClientServicePrincipalID string
	FederatedIssuer          string
	FederatedSubject         string
}

func captureLiveRoleTrustsContext(outdir, infraDir string, env []string, progressWriter io.Writer) error {
	outputs, err := loadTofuOutputs(infraDir, "tofu")
	if err != nil {
		return fmt.Errorf("load tofu outputs for role-trusts context: %w", err)
	}

	manifest, err := roleTrustCanaryManifestFromOutputs(outputs)
	if err != nil {
		return err
	}

	artifact := liveRoleTrustsContextArtifact{}

	_, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType",
		"az rest (role-trusts service principals)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if !visible {
		artifact.ExpectZeroRows = true
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "role_trusts.service_principals")
		return writeLiveRoleTrustsContext(outdir, artifact)
	}

	apiOwners, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/applications/"+manifest.APIApplicationID+"/owners?$select=id,displayName,userPrincipalName,appId,servicePrincipalType",
		"az rest (role-trusts api application owners)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if !visible {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "role_trusts.applications["+manifest.APIApplicationID+"].owners")
	} else {
		if len(apiOwners) == 0 {
			return fmt.Errorf("role-trusts canary application %q did not expose any owners", manifest.APIApplicationID)
		}
		for _, owner := range apiOwners {
			ownerID := strings.TrimSpace(mapStringValue(owner, "id"))
			if ownerID == "" {
				continue
			}
			artifact.ExpectedTrusts = append(artifact.ExpectedTrusts, liveRoleTrustTruth{
				Confidence:       "confirmed",
				ControlPrimitive: "change-auth-material",
				EvidenceType:     "graph-owner",
				RelatedIDs:       []string{ownerID, manifest.APIApplicationID},
				SourceObjectID:   ownerID,
				SourceType:       roleTrustGraphObjectType(owner),
				TargetObjectID:   manifest.APIApplicationID,
				TargetType:       "Application",
				TrustType:        "app-owner",
			})
		}
	}

	apiFederatedCredentials, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/applications/"+manifest.APIApplicationID+"/federatedIdentityCredentials?$select=id,issuer,subject",
		"az rest (role-trusts api federated credentials)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if !visible {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "role_trusts.applications["+manifest.APIApplicationID+"].federated_credentials")
	} else {
		matched := false
		for _, credential := range apiFederatedCredentials {
			if strings.TrimSpace(mapStringValue(credential, "issuer")) != manifest.FederatedIssuer {
				continue
			}
			if strings.TrimSpace(mapStringValue(credential, "subject")) != manifest.FederatedSubject {
				continue
			}
			credentialID := strings.TrimSpace(mapStringValue(credential, "id"))
			artifact.ExpectedTrusts = append(artifact.ExpectedTrusts, liveRoleTrustTruth{
				Confidence:       "confirmed",
				ControlPrimitive: "existing-federated-credential",
				EvidenceType:     "graph-federated-credential",
				RelatedIDs:       roleTrustFilterNonEmpty(manifest.APIApplicationID, credentialID, manifest.APIServicePrincipalID),
				SourceObjectID:   manifest.APIApplicationID,
				SourceType:       "Application",
				SummaryContains:  roleTrustFilterNonEmpty(manifest.FederatedIssuer, manifest.FederatedSubject),
				TargetObjectID:   manifest.APIServicePrincipalID,
				TargetType:       "ServicePrincipal",
				TrustType:        "federated-credential",
			})
			matched = true
			break
		}
		if !matched {
			return fmt.Errorf("role-trusts canary application %q did not expose the expected federated credential", manifest.APIApplicationID)
		}
	}

	apiServicePrincipalOwners, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/servicePrincipals/"+manifest.APIServicePrincipalID+"/owners?$select=id,displayName,userPrincipalName,appId,servicePrincipalType",
		"az rest (role-trusts api service principal owners)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if !visible {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "role_trusts.service_principals["+manifest.APIServicePrincipalID+"].owners")
	} else {
		if len(apiServicePrincipalOwners) == 0 {
			return fmt.Errorf("role-trusts canary service principal %q did not expose any owners", manifest.APIServicePrincipalID)
		}
		for _, owner := range apiServicePrincipalOwners {
			ownerID := strings.TrimSpace(mapStringValue(owner, "id"))
			if ownerID == "" {
				continue
			}
			artifact.ExpectedTrusts = append(artifact.ExpectedTrusts, liveRoleTrustTruth{
				Confidence:       "confirmed",
				ControlPrimitive: "owner-control",
				EvidenceType:     "graph-owner",
				RelatedIDs:       []string{ownerID, manifest.APIServicePrincipalID},
				SourceObjectID:   ownerID,
				SourceType:       roleTrustGraphObjectType(owner),
				TargetObjectID:   manifest.APIServicePrincipalID,
				TargetType:       "ServicePrincipal",
				TrustType:        "service-principal-owner",
			})
		}
	}

	clientAssignments, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/servicePrincipals/"+manifest.ClientServicePrincipalID+"/appRoleAssignments?$select=id,resourceId",
		"az rest (role-trusts client app-role assignments)",
		env,
		progressWriter,
	)
	if err != nil {
		return err
	}
	if !visible {
		artifact.RequiredIssueCollectors = append(artifact.RequiredIssueCollectors, "role_trusts.service_principals["+manifest.ClientServicePrincipalID+"].app_role_assignments")
	} else {
		matched := false
		for _, assignment := range clientAssignments {
			if strings.TrimSpace(mapStringValue(assignment, "resourceId")) != manifest.APIServicePrincipalID {
				continue
			}
			assignmentID := strings.TrimSpace(mapStringValue(assignment, "id"))
			artifact.ExpectedTrusts = append(artifact.ExpectedTrusts, liveRoleTrustTruth{
				Confidence:       "confirmed",
				ControlPrimitive: "existing-app-role-assignment",
				EvidenceType:     "graph-app-role-assignment",
				RelatedIDs:       roleTrustFilterNonEmpty(manifest.ClientServicePrincipalID, assignmentID, manifest.APIServicePrincipalID),
				SourceObjectID:   manifest.ClientServicePrincipalID,
				SourceType:       "ServicePrincipal",
				TargetObjectID:   manifest.APIServicePrincipalID,
				TargetType:       "ServicePrincipal",
				TrustType:        "app-to-service-principal",
			})
			matched = true
			break
		}
		if !matched {
			return fmt.Errorf("role-trusts client service principal %q did not expose the expected app-role assignment to %q", manifest.ClientServicePrincipalID, manifest.APIServicePrincipalID)
		}
	}

	return writeLiveRoleTrustsContext(outdir, artifact)
}

func writeLiveRoleTrustsContext(outdir string, artifact liveRoleTrustsContextArtifact) error {
	sort.Strings(artifact.RequiredIssueCollectors)
	sort.SliceStable(artifact.ExpectedTrusts, func(i, j int) bool {
		left := artifact.ExpectedTrusts[i]
		right := artifact.ExpectedTrusts[j]
		if left.TrustType != right.TrustType {
			return left.TrustType < right.TrustType
		}
		if left.SourceObjectID != right.SourceObjectID {
			return left.SourceObjectID < right.SourceObjectID
		}
		return left.TargetObjectID < right.TargetObjectID
	})
	if err := WriteJSON(filepath.Join(outdir, "live-role-trusts-context.json"), artifact); err != nil {
		return fmt.Errorf("write live role-trusts context artifact: %w", err)
	}
	return nil
}

func roleTrustCanaryManifestFromOutputs(outputs map[string]tofuOutputEntry) (roleTrustCanaryManifest, error) {
	entry, ok := outputs["role_trusts"]
	if !ok {
		return roleTrustCanaryManifest{}, fmt.Errorf("missing tofu output %q", "role_trusts")
	}
	roleTrusts, ok := entry.Value.(map[string]any)
	if !ok || roleTrusts == nil {
		return roleTrustCanaryManifest{}, fmt.Errorf("tofu output %q was not an object", "role_trusts")
	}

	applications, _ := roleTrusts["applications"].(map[string]any)
	apiApplication, _ := applications["api"].(map[string]any)
	servicePrincipals, _ := roleTrusts["service_principals"].(map[string]any)
	apiServicePrincipal, _ := servicePrincipals["api"].(map[string]any)
	clientServicePrincipal, _ := servicePrincipals["client"].(map[string]any)
	federatedCredential, _ := roleTrusts["federated_credential"].(map[string]any)

	manifest := roleTrustCanaryManifest{
		APIApplicationID:         strings.TrimSpace(mapStringValue(apiApplication, "object_id")),
		APIServicePrincipalID:    strings.TrimSpace(mapStringValue(apiServicePrincipal, "object_id")),
		ClientServicePrincipalID: strings.TrimSpace(mapStringValue(clientServicePrincipal, "object_id")),
		FederatedIssuer:          strings.TrimSpace(mapStringValue(federatedCredential, "issuer")),
		FederatedSubject:         strings.TrimSpace(mapStringValue(federatedCredential, "subject")),
	}

	switch {
	case manifest.APIApplicationID == "":
		return roleTrustCanaryManifest{}, fmt.Errorf("role_trusts output is missing the api application object_id")
	case manifest.APIServicePrincipalID == "":
		return roleTrustCanaryManifest{}, fmt.Errorf("role_trusts output is missing the api service principal object_id")
	case manifest.ClientServicePrincipalID == "":
		return roleTrustCanaryManifest{}, fmt.Errorf("role_trusts output is missing the client service principal object_id")
	case manifest.FederatedIssuer == "":
		return roleTrustCanaryManifest{}, fmt.Errorf("role_trusts output is missing the federated credential issuer")
	case manifest.FederatedSubject == "":
		return roleTrustCanaryManifest{}, fmt.Errorf("role_trusts output is missing the federated credential subject")
	}

	return manifest, nil
}

func roleTrustGraphObjectType(object map[string]any) string {
	if strings.TrimSpace(mapStringValue(object, "userPrincipalName")) != "" {
		return "User"
	}
	if strings.TrimSpace(mapStringValue(object, "servicePrincipalType")) != "" || strings.TrimSpace(mapStringValue(object, "appId")) != "" {
		return "ServicePrincipal"
	}
	return "DirectoryObject"
}

func roleTrustFilterNonEmpty(values ...string) []string {
	filtered := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		filtered = append(filtered, trimmed)
	}
	return filtered
}
