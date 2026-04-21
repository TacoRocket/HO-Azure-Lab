package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
)

type liveAppCredentialsContextArtifact struct {
	ExpectZeroRows                 bool                                     `json:"expect_zero_rows"`
	OwnedApplications              []liveAppCredentialApplicationTruth      `json:"owned_applications"`
	OwnedServicePrincipals         []liveAppCredentialServicePrincipalTruth `json:"owned_service_principals"`
	ExistingFederatedApplications  []liveAppCredentialApplicationTruth      `json:"existing_federated_applications"`
	ExistingCredentialApplications []liveAppCredentialExistingCredential    `json:"existing_credential_applications"`
}

type liveAppCredentialApplicationTruth struct {
	ObjectID                    string `json:"object_id"`
	DisplayName                 string `json:"display_name"`
	BackingServicePrincipalID   string `json:"backing_service_principal_id,omitempty"`
	BackingServicePrincipalName string `json:"backing_service_principal_name,omitempty"`
}

type liveAppCredentialServicePrincipalTruth struct {
	ObjectID    string `json:"object_id"`
	DisplayName string `json:"display_name"`
}

type liveAppCredentialExistingCredential struct {
	ObjectID                    string `json:"object_id"`
	DisplayName                 string `json:"display_name"`
	BackingServicePrincipalID   string `json:"backing_service_principal_id,omitempty"`
	BackingServicePrincipalName string `json:"backing_service_principal_name,omitempty"`
	CredentialType              string `json:"credential_type"`
}

type appCredentialApplicationCandidate struct {
	DisplayName                 string
	ObjectID                    string
	AppID                       string
	BackingServicePrincipalID   string
	BackingServicePrincipalName string
}

type appCredentialServicePrincipalCandidate struct {
	DisplayName string
	ObjectID    string
}

type graphCollectionResponse struct {
	Value []map[string]any `json:"value"`
}

func captureLiveAppCredentialsContext(outdir, infraDir string, env []string, progressWriter io.Writer) error {
	currentContext := liveAzureContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-azure-context.json"), &currentContext); err != nil {
		return fmt.Errorf("load live azure context: %w", err)
	}

	outputs, err := loadTofuOutputs(infraDir, "tofu")
	if err != nil {
		return fmt.Errorf("load tofu outputs for app-credentials context: %w", err)
	}

	viewpointPrincipals, applicationCandidates, servicePrincipalCandidates, err := appCredentialCanaryCandidates(outputs)
	if err != nil {
		return err
	}

	artifact := liveAppCredentialsContextArtifact{
		ExpectZeroRows: appCredentialExpectZeroRows(currentContext.PrincipalID, viewpointPrincipals),
	}

	for _, candidate := range applicationCandidates {
		application, visible, err := graphApplicationCandidate(candidate, env, progressWriter)
		if err != nil {
			return err
		}
		if !visible {
			continue
		}
		applicationObjectID := strings.TrimSpace(mapStringValue(application, "id"))
		if applicationObjectID == "" {
			applicationObjectID = strings.TrimSpace(candidate.ObjectID)
		}
		applicationDisplayName := strings.TrimSpace(mapStringValue(application, "displayName"))
		if applicationDisplayName == "" {
			applicationDisplayName = strings.TrimSpace(candidate.DisplayName)
		}
		if applicationObjectID == "" {
			continue
		}
		owners, visible, err := graphCollectionByURL(
			"https://graph.microsoft.com/v1.0/applications/"+url.PathEscape(applicationObjectID)+"/owners?$select=id",
			"az rest (app-credentials application owners)",
			env,
			progressWriter,
		)
		if err != nil {
			return err
		}
		if !visible {
			continue
		}
		if appCredentialOwnerVisible(owners, currentContext.PrincipalID) {
			artifact.OwnedApplications = append(artifact.OwnedApplications, liveAppCredentialApplicationTruth{
				ObjectID:                    applicationObjectID,
				DisplayName:                 applicationDisplayName,
				BackingServicePrincipalID:   candidate.BackingServicePrincipalID,
				BackingServicePrincipalName: candidate.BackingServicePrincipalName,
			})
		}

		federatedCredentials, visible, err := graphCollectionByURL(
			"https://graph.microsoft.com/v1.0/applications/"+url.PathEscape(applicationObjectID)+"/federatedIdentityCredentials?$select=id",
			"az rest (app-credentials federated credentials)",
			env,
			progressWriter,
		)
		if err != nil {
			return err
		}
		if visible && len(federatedCredentials) > 0 {
			artifact.ExistingFederatedApplications = append(artifact.ExistingFederatedApplications, liveAppCredentialApplicationTruth{
				ObjectID:                    applicationObjectID,
				DisplayName:                 applicationDisplayName,
				BackingServicePrincipalID:   candidate.BackingServicePrincipalID,
				BackingServicePrincipalName: candidate.BackingServicePrincipalName,
			})
		}

		if graphCredentialCount(application, "passwordCredentials") > 0 {
			artifact.ExistingCredentialApplications = append(artifact.ExistingCredentialApplications, liveAppCredentialExistingCredential{
				ObjectID:                    applicationObjectID,
				DisplayName:                 applicationDisplayName,
				BackingServicePrincipalID:   candidate.BackingServicePrincipalID,
				BackingServicePrincipalName: candidate.BackingServicePrincipalName,
				CredentialType:              "password",
			})
		}
		if graphCredentialCount(application, "keyCredentials") > 0 {
			artifact.ExistingCredentialApplications = append(artifact.ExistingCredentialApplications, liveAppCredentialExistingCredential{
				ObjectID:                    applicationObjectID,
				DisplayName:                 applicationDisplayName,
				BackingServicePrincipalID:   candidate.BackingServicePrincipalID,
				BackingServicePrincipalName: candidate.BackingServicePrincipalName,
				CredentialType:              "key",
			})
		}
	}

	for _, candidate := range servicePrincipalCandidates {
		owners, visible, err := graphCollectionByURL(
			"https://graph.microsoft.com/v1.0/servicePrincipals/"+url.PathEscape(candidate.ObjectID)+"/owners?$select=id",
			"az rest (app-credentials service principal owners)",
			env,
			progressWriter,
		)
		if err != nil {
			return err
		}
		if !visible {
			continue
		}
		if appCredentialOwnerVisible(owners, currentContext.PrincipalID) {
			artifact.OwnedServicePrincipals = append(artifact.OwnedServicePrincipals, liveAppCredentialServicePrincipalTruth{
				ObjectID:    candidate.ObjectID,
				DisplayName: candidate.DisplayName,
			})
		}
	}

	if err := WriteJSON(filepath.Join(outdir, "live-app-credentials-context.json"), artifact); err != nil {
		return fmt.Errorf("write live app-credentials context artifact: %w", err)
	}
	return nil
}

func appCredentialCanaryCandidates(outputs map[string]tofuOutputEntry) (map[string]string, []appCredentialApplicationCandidate, []appCredentialServicePrincipalCandidate, error) {
	viewpointPrincipals := map[string]string{}
	applicationCandidates := []appCredentialApplicationCandidate{}
	servicePrincipalCandidates := []appCredentialServicePrincipalCandidate{}

	validationViewpointsEntry, ok := outputs["validation_viewpoints"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing tofu output %q", "validation_viewpoints")
	}
	validationViewpoints, ok := validationViewpointsEntry.Value.(map[string]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("tofu output %q was not an object", "validation_viewpoints")
	}
	for key, value := range validationViewpoints {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		displayName, _ := item["display_name"].(string)
		clientID, _ := item["client_id"].(string)
		principalObjectID, _ := item["principal_object_id"].(string)
		viewpointPrincipals[key] = strings.TrimSpace(principalObjectID)
		applicationCandidates = append(applicationCandidates, appCredentialApplicationCandidate{
			DisplayName:                 strings.TrimSpace(displayName),
			AppID:                       strings.TrimSpace(clientID),
			BackingServicePrincipalID:   strings.TrimSpace(principalObjectID),
			BackingServicePrincipalName: strings.TrimSpace(displayName),
		})
		servicePrincipalCandidates = append(servicePrincipalCandidates, appCredentialServicePrincipalCandidate{
			DisplayName: strings.TrimSpace(displayName),
			ObjectID:    strings.TrimSpace(principalObjectID),
		})
	}

	roleTrustsEntry, ok := outputs["role_trusts"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("missing tofu output %q", "role_trusts")
	}
	roleTrusts, ok := roleTrustsEntry.Value.(map[string]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("tofu output %q was not an object", "role_trusts")
	}
	roleTrustApplications, _ := roleTrusts["applications"].(map[string]any)
	roleTrustServicePrincipals, _ := roleTrusts["service_principals"].(map[string]any)

	for key, value := range roleTrustApplications {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		backingServicePrincipal, _ := roleTrustServicePrincipals[key].(map[string]any)
		applicationCandidates = append(applicationCandidates, appCredentialApplicationCandidate{
			DisplayName:                 strings.TrimSpace(mapStringValue(item, "display_name")),
			ObjectID:                    strings.TrimSpace(mapStringValue(item, "object_id")),
			AppID:                       strings.TrimSpace(mapStringValue(item, "client_id")),
			BackingServicePrincipalID:   strings.TrimSpace(mapStringValue(backingServicePrincipal, "object_id")),
			BackingServicePrincipalName: strings.TrimSpace(mapStringValue(backingServicePrincipal, "display_name")),
		})
	}
	for _, value := range roleTrustServicePrincipals {
		item, ok := value.(map[string]any)
		if !ok {
			continue
		}
		servicePrincipalCandidates = append(servicePrincipalCandidates, appCredentialServicePrincipalCandidate{
			DisplayName: strings.TrimSpace(mapStringValue(item, "display_name")),
			ObjectID:    strings.TrimSpace(mapStringValue(item, "object_id")),
		})
	}

	return viewpointPrincipals, applicationCandidates, servicePrincipalCandidates, nil
}

func appCredentialExpectZeroRows(currentPrincipalID string, viewpointPrincipals map[string]string) bool {
	current := strings.TrimSpace(currentPrincipalID)
	if current == "" {
		return false
	}
	for _, principalID := range viewpointPrincipals {
		if strings.TrimSpace(principalID) == current {
			return true
		}
	}
	return false
}

func graphApplicationCandidate(candidate appCredentialApplicationCandidate, env []string, progressWriter io.Writer) (map[string]any, bool, error) {
	if strings.TrimSpace(candidate.ObjectID) != "" {
		return graphObjectByURL(
			"https://graph.microsoft.com/v1.0/applications/"+url.PathEscape(candidate.ObjectID)+"?$select=id,displayName,appId,passwordCredentials,keyCredentials",
			"az rest (app-credentials application)",
			env,
			progressWriter,
		)
	}
	if strings.TrimSpace(candidate.AppID) == "" {
		return nil, false, nil
	}
	items, visible, err := graphCollectionByURL(
		"https://graph.microsoft.com/v1.0/applications?$filter=appId%20eq%20'"+url.QueryEscape(strings.TrimSpace(candidate.AppID))+"'&$select=id,displayName,appId,passwordCredentials,keyCredentials",
		"az rest (app-credentials application by appId)",
		env,
		progressWriter,
	)
	if err != nil || !visible || len(items) == 0 {
		return nil, visible, err
	}
	return items[0], true, nil
}

func graphObjectByURL(requestURL, label string, env []string, progressWriter io.Writer) (map[string]any, bool, error) {
	cmd := exec.Command("az", "rest", "--method", "get", "--url", requestURL, "--output", "json")
	output, err := runProgressCommand(label, "", env, progressWriter, cmd)
	if err != nil {
		if graphReadDenied(output) || graphNotFound(output) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%s failed: %s", label, strings.TrimSpace(string(output)))
	}
	payload := map[string]any{}
	if err := json.Unmarshal(output, &payload); err != nil {
		return nil, false, fmt.Errorf("parse %s output: %w", label, err)
	}
	return payload, true, nil
}

func graphCollectionByURL(requestURL, label string, env []string, progressWriter io.Writer) ([]map[string]any, bool, error) {
	cmd := exec.Command("az", "rest", "--method", "get", "--url", requestURL, "--output", "json")
	output, err := runProgressCommand(label, "", env, progressWriter, cmd)
	if err != nil {
		if graphReadDenied(output) || graphNotFound(output) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%s failed: %s", label, strings.TrimSpace(string(output)))
	}
	response := graphCollectionResponse{}
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, false, fmt.Errorf("parse %s output: %w", label, err)
	}
	return response.Value, true, nil
}

func appCredentialOwnerVisible(owners []map[string]any, currentPrincipalID string) bool {
	current := strings.TrimSpace(currentPrincipalID)
	if current == "" {
		return false
	}
	for _, owner := range owners {
		if strings.TrimSpace(mapStringValue(owner, "id")) == current {
			return true
		}
	}
	return false
}

func graphCredentialCount(object map[string]any, field string) int {
	items, ok := object[field].([]any)
	if !ok {
		return 0
	}
	return len(items)
}

func graphReadDenied(output []byte) bool {
	text := strings.ToLower(strings.TrimSpace(string(output)))
	return strings.Contains(text, "authorization_requestdenied") ||
		strings.Contains(text, "insufficient privileges") ||
		strings.Contains(text, "access is denied") ||
		strings.Contains(text, "authorization failed") ||
		strings.Contains(text, "required scopes are missing in the token") ||
		strings.Contains(text, "applications without a signed-in user are not allowed access to this report or data")
}

func graphNotFound(output []byte) bool {
	text := strings.ToLower(strings.TrimSpace(string(output)))
	return strings.Contains(text, "request_resource_not_found") ||
		strings.Contains(text, "\"code\": \"itemnotfound\"") ||
		strings.Contains(text, "\"code\":\"itemnotfound\"")
}
