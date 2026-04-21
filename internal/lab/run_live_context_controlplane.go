package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	azureMLValidationAPIVersion   = "2024-04-01"
	eventGridValidationAPIVersion = "2025-02-15"
)

type liveEventGridContextArtifact struct {
	Routes []liveEventGridTruth `json:"routes"`
}

type liveEventGridTruth struct {
	ID                  string   `json:"id"`
	Name                string   `json:"route"`
	Classification      string   `json:"classification"`
	SourceID            string   `json:"source_id"`
	SourceType          string   `json:"source_type"`
	DestinationType     string   `json:"destination_type"`
	DestinationTargetID string   `json:"destination_target_id,omitempty"`
	ExternalDelivery    bool     `json:"external_delivery"`
	ProvisioningState   string   `json:"provisioning_state,omitempty"`
	IdentityType        string   `json:"identity_type,omitempty"`
	IdentityID          string   `json:"identity_id,omitempty"`
	EventDeliverySchema string   `json:"event_delivery_schema,omitempty"`
	IncludedEventTypes  []string `json:"included_event_types"`
	RelatedIDs          []string `json:"related_ids"`
}

type liveAzureMLContextArtifact struct {
	Workspaces []liveAzureMLTruth `json:"workspaces"`
}

type liveAzureMLTruth struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Classification        string   `json:"classification"`
	ResourceGroup         string   `json:"resource_group"`
	Location              string   `json:"location,omitempty"`
	WorkspaceKind         string   `json:"workspace_kind,omitempty"`
	State                 string   `json:"state,omitempty"`
	PublicNetworkAccess   string   `json:"public_network_access,omitempty"`
	IdentityType          string   `json:"identity_type,omitempty"`
	PrincipalID           string   `json:"principal_id,omitempty"`
	IdentityIDs           []string `json:"identity_ids"`
	ComputeCount          int      `json:"compute_count"`
	ComputeTypes          []string `json:"compute_types"`
	JobCount              int      `json:"job_count"`
	JobTypes              []string `json:"job_types"`
	ScheduleCount         int      `json:"schedule_count"`
	ScheduleTriggerTypes  []string `json:"schedule_trigger_types"`
	EndpointCount         int      `json:"endpoint_count"`
	EndpointAuthModes     []string `json:"endpoint_auth_modes"`
	EndpointPublicAccess  []string `json:"endpoint_public_access"`
	DatastoreCount        int      `json:"datastore_count"`
	DatastoreTypes        []string `json:"datastore_types"`
	StorageAccountID      string   `json:"storage_account_id,omitempty"`
	KeyVaultID            string   `json:"key_vault_id,omitempty"`
	ContainerRegistryID   string   `json:"container_registry_id,omitempty"`
	ApplicationInsightsID string   `json:"application_insights_id,omitempty"`
	RelatedIDs            []string `json:"related_ids"`
}

type azAzureMLWorkspaceListResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
}

type azAzureMLWorkspaceShowResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	Kind          string `json:"kind"`
	Identity      struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	Properties struct {
		ProvisioningState   string `json:"provisioningState"`
		PublicNetworkAccess string `json:"publicNetworkAccess"`
		StorageAccount      string `json:"storageAccount"`
		KeyVault            string `json:"keyVault"`
		ContainerRegistry   string `json:"containerRegistry"`
		ApplicationInsights string `json:"applicationInsights"`
	} `json:"properties"`
}

func captureLiveLogicAppsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Logic/workflows", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (logic-apps validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(listOutput)))
	}
	workflows := []azLogicAppResource{}
	if err := json.Unmarshal(listOutput, &workflows); err != nil {
		return fmt.Errorf("parse az resource list output: %w", err)
	}

	truths := make([]liveLogicAppTruth, 0, len(workflows))
	for _, listed := range workflows {
		if strings.TrimSpace(listed.ID) == "" {
			continue
		}
		showCmd := exec.Command("az", "resource", "show", "--ids", listed.ID, "--api-version", "2019-05-01", "--output", "json")
		showOutput, err := runProgressCommand("az resource show (logic-apps validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", listed.ID, strings.TrimSpace(string(showOutput)))
		}
		workflow := azLogicAppResource{}
		if err := json.Unmarshal(showOutput, &workflow); err != nil {
			return fmt.Errorf("parse az resource show output for %s: %w", listed.ID, err)
		}

		triggerTypes := logicAppTriggerTypesFromAzure(workflow.Properties.Definition)
		recurrenceSummary := logicAppRecurrenceSummaryFromAzure(workflow.Properties.Definition)
		downstreamKinds := logicAppDownstreamActionKindsFromAzure(workflow.Properties.Definition)
		hasRequestTrigger := logicAppHasRequestTriggerFromAzure(workflow.Properties.Definition)
		truths = append(truths, liveLogicAppTruth{
			ID:                               strings.TrimSpace(workflow.ID),
			Name:                             strings.TrimSpace(workflow.Name),
			ResourceGroup:                    strings.TrimSpace(workflow.ResourceGroup),
			Location:                         strings.TrimSpace(workflow.Location),
			State:                            strings.TrimSpace(workflow.Properties.State),
			WorkflowKind:                     strings.TrimSpace(workflow.Kind),
			IdentityType:                     strings.TrimSpace(workflow.Identity.Type),
			PrincipalID:                      strings.TrimSpace(workflow.Identity.PrincipalID),
			ClientID:                         strings.TrimSpace(workflow.Identity.ClientID),
			IdentityIDs:                      logicAppIdentityIDsFromAzure(workflow.ID, workflow.Identity.Type, workflow.Identity.UserAssignedIdentities),
			TriggerTypes:                     triggerTypes,
			ExternallyCallableRequestTrigger: hasRequestTrigger,
			RecurrenceSummary:                recurrenceSummary,
			DownstreamActionKinds:            downstreamKinds,
			Classification: logicAppClassificationFromAzure(
				hasRequestTrigger,
				recurrenceSummary != "",
				strings.TrimSpace(workflow.Identity.Type) != "",
				len(downstreamKinds) > 0,
			),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveLogicAppsContextArtifact{Workflows: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-logic-apps-context.json"), artifact); err != nil {
		return fmt.Errorf("write live logic apps context artifact: %w", err)
	}
	return nil
}

func captureLiveAutomationContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Automation/automationAccounts", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (automation validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(listOutput)))
	}
	accounts := []azAutomationAccountResource{}
	if err := json.Unmarshal(listOutput, &accounts); err != nil {
		return fmt.Errorf("parse az resource list output: %w", err)
	}

	truths := make([]liveAutomationTruth, 0, len(accounts))
	for _, listed := range accounts {
		if strings.TrimSpace(listed.ID) == "" {
			continue
		}
		showCmd := exec.Command("az", "resource", "show", "--ids", listed.ID, "--api-version", "2024-10-23", "--output", "json")
		showOutput, err := runProgressCommand("az resource show (automation validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", listed.ID, strings.TrimSpace(string(showOutput)))
		}
		account := azAutomationAccountResource{}
		if err := json.Unmarshal(showOutput, &account); err != nil {
			return fmt.Errorf("parse az resource show output for %s: %w", listed.ID, err)
		}

		runbooks, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "runbooks")
		if err != nil {
			return err
		}
		schedules, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "schedules")
		if err != nil {
			return err
		}
		jobSchedules, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "jobSchedules")
		if err != nil {
			return err
		}
		webhooks, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "webhooks")
		if err != nil {
			return err
		}
		credentials, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "credentials")
		if err != nil {
			return err
		}
		certificates, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "certificates")
		if err != nil {
			return err
		}
		connections, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "connections")
		if err != nil {
			return err
		}
		variables, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "variables")
		if err != nil {
			return err
		}
		hybridGroups, err := automationChildResources(workingDir, env, progressWriter, listed.ID, "hybridRunbookWorkerGroups")
		if err != nil {
			return err
		}

		truths = append(truths, liveAutomationTruth{
			ID:                     strings.TrimSpace(account.ID),
			Name:                   strings.TrimSpace(account.Name),
			ResourceGroup:          strings.TrimSpace(account.ResourceGroup),
			Location:               strings.TrimSpace(account.Location),
			State:                  strings.TrimSpace(account.State),
			SKUName:                strings.TrimSpace(account.SKU.Name),
			IdentityType:           strings.TrimSpace(account.Identity.Type),
			PrincipalID:            strings.TrimSpace(account.Identity.PrincipalID),
			ClientID:               strings.TrimSpace(account.Identity.ClientID),
			IdentityIDs:            automationIdentityIDsFromAzure(account.ID, account.Identity.Type, account.Identity.UserAssignedIdentities),
			RunbookCount:           intValuePtr(len(runbooks)),
			PublishedRunbookCount:  intValuePtr(automationPublishedRunbookCountFromAzure(runbooks)),
			ScheduleCount:          intValuePtr(len(schedules)),
			JobScheduleCount:       intValuePtr(len(jobSchedules)),
			WebhookCount:           intValuePtr(len(webhooks)),
			HybridWorkerGroupCount: intValuePtr(len(hybridGroups)),
			CredentialCount:        intValuePtr(len(credentials)),
			CertificateCount:       intValuePtr(len(certificates)),
			ConnectionCount:        intValuePtr(len(connections)),
			VariableCount:          intValuePtr(len(variables)),
			EncryptedVariableCount: intValuePtr(automationEncryptedVariableCountFromAzure(variables)),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveAutomationContextArtifact{AutomationAccounts: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-automation-context.json"), artifact); err != nil {
		return fmt.Errorf("write live automation context artifact: %w", err)
	}
	return nil
}

func captureLiveAzureMLContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.MachineLearningServices/workspaces", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (azure-ml validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(listOutput)))
	}
	workspaces := []azAzureMLWorkspaceListResource{}
	if err := json.Unmarshal(listOutput, &workspaces); err != nil {
		return fmt.Errorf("parse az resource list output: %w", err)
	}

	truths := make([]liveAzureMLTruth, 0, len(workspaces))
	for _, listed := range workspaces {
		if strings.TrimSpace(listed.ID) == "" {
			continue
		}
		showCmd := exec.Command("az", "resource", "show", "--ids", listed.ID, "--api-version", azureMLValidationAPIVersion, "--output", "json")
		showOutput, err := runProgressCommand("az resource show (azure-ml validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", listed.ID, strings.TrimSpace(string(showOutput)))
		}
		workspace := azAzureMLWorkspaceShowResource{}
		if err := json.Unmarshal(showOutput, &workspace); err != nil {
			return fmt.Errorf("parse az resource show output for %s: %w", listed.ID, err)
		}

		computes, err := azureMLChildResources(workingDir, env, progressWriter, listed.ID, "computes")
		if err != nil {
			return err
		}
		jobs, err := azureMLChildResources(workingDir, env, progressWriter, listed.ID, "jobs")
		if err != nil {
			return err
		}
		schedules, err := azureMLChildResources(workingDir, env, progressWriter, listed.ID, "schedules")
		if err != nil {
			return err
		}
		endpoints, err := azureMLChildResources(workingDir, env, progressWriter, listed.ID, "onlineEndpoints")
		if err != nil {
			return err
		}
		datastores, err := azureMLChildResources(workingDir, env, progressWriter, listed.ID, "datastores")
		if err != nil {
			return err
		}

		truths = append(truths, liveAzureMLTruth{
			ID:                    strings.TrimSpace(workspace.ID),
			Name:                  firstNonEmptyString(strings.TrimSpace(workspace.Name), strings.TrimSpace(listed.Name)),
			Classification:        azureMLClassificationFromAzure(len(computes) > 0, len(jobs) > 0, len(endpoints) > 0, len(schedules) > 0),
			ResourceGroup:         firstNonEmptyString(strings.TrimSpace(workspace.ResourceGroup), strings.TrimSpace(listed.ResourceGroup)),
			Location:              firstNonEmptyString(strings.TrimSpace(workspace.Location), strings.TrimSpace(listed.Location)),
			WorkspaceKind:         strings.TrimSpace(workspace.Kind),
			State:                 strings.TrimSpace(workspace.Properties.ProvisioningState),
			PublicNetworkAccess:   strings.TrimSpace(workspace.Properties.PublicNetworkAccess),
			IdentityType:          strings.TrimSpace(workspace.Identity.Type),
			PrincipalID:           strings.TrimSpace(workspace.Identity.PrincipalID),
			IdentityIDs:           azureMLIdentityIDsFromAzure(workspace.ID, workspace.Identity.Type, workspace.Identity.UserAssignedIdentities),
			ComputeCount:          len(computes),
			ComputeTypes:          azureMLComputeTypesFromAzure(computes),
			JobCount:              len(jobs),
			JobTypes:              azureMLJobTypesFromAzure(jobs),
			ScheduleCount:         len(schedules),
			ScheduleTriggerTypes:  azureMLScheduleTriggerTypesFromAzure(schedules),
			EndpointCount:         len(endpoints),
			EndpointAuthModes:     azureMLEndpointAuthModesFromAzure(endpoints),
			EndpointPublicAccess:  azureMLEndpointPublicAccessFromAzure(endpoints),
			DatastoreCount:        len(datastores),
			DatastoreTypes:        azureMLDatastoreTypesFromAzure(datastores),
			StorageAccountID:      strings.TrimSpace(workspace.Properties.StorageAccount),
			KeyVaultID:            strings.TrimSpace(workspace.Properties.KeyVault),
			ContainerRegistryID:   strings.TrimSpace(workspace.Properties.ContainerRegistry),
			ApplicationInsightsID: strings.TrimSpace(workspace.Properties.ApplicationInsights),
			RelatedIDs: azureMLRelatedIDsFromAzure(
				workspace.ID,
				azureMLIdentityIDsFromAzure(workspace.ID, workspace.Identity.Type, workspace.Identity.UserAssignedIdentities),
				workspace.Properties.StorageAccount,
				workspace.Properties.KeyVault,
				workspace.Properties.ContainerRegistry,
				workspace.Properties.ApplicationInsights,
				azureMLResourceIDsFromAzure(datastores),
			),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveAzureMLContextArtifact{Workspaces: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-azure-ml-context.json"), artifact); err != nil {
		return fmt.Errorf("write live azure-ml context artifact: %w", err)
	}
	return nil
}

func captureLiveEventGridContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.EventGrid/eventSubscriptions", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (event-grid validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(listOutput)))
	}

	listedRoutes := []map[string]any{}
	if err := json.Unmarshal(listOutput, &listedRoutes); err != nil {
		return fmt.Errorf("parse az resource list output: %w", err)
	}

	truths := make([]liveEventGridTruth, 0, len(listedRoutes))
	for _, listed := range listedRoutes {
		resourceID := strings.TrimSpace(stringValue(listed["id"]))
		if resourceID == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", resourceID, "--api-version", eventGridValidationAPIVersion, "--output", "json")
		showOutput, err := runProgressCommand("az resource show (event-grid validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", resourceID, strings.TrimSpace(string(showOutput)))
		}

		route := map[string]any{}
		if err := json.Unmarshal(showOutput, &route); err != nil {
			return fmt.Errorf("parse az resource show output for %s: %w", resourceID, err)
		}

		truths = append(truths, eventGridTruthFromAzure(route))
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveEventGridContextArtifact{Routes: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-event-grid-context.json"), artifact); err != nil {
		return fmt.Errorf("write live event-grid context artifact: %w", err)
	}
	return nil
}

func automationChildResources(workingDir string, env []string, progressWriter io.Writer, accountID, childPath string) ([]map[string]any, error) {
	url := "https://management.azure.com" + strings.TrimSpace(accountID) + "/" + childPath + "?api-version=2024-10-23"
	cmd := exec.Command("az", "rest", "--method", "get", "--url", url, "--output", "json")
	output, err := runProgressCommand("az rest ("+childPath+" validation context)", workingDir, env, progressWriter, cmd)
	if err != nil {
		return nil, fmt.Errorf("az rest failed for %s on %s: %s", childPath, accountID, strings.TrimSpace(string(output)))
	}
	response := azAutomationListResponse{}
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("parse az rest output for %s on %s: %w", childPath, accountID, err)
	}
	return response.Value, nil
}

func azureMLChildResources(workingDir string, env []string, progressWriter io.Writer, workspaceID, childPath string) ([]map[string]any, error) {
	url := "https://management.azure.com" + strings.TrimSpace(workspaceID) + "/" + childPath + "?api-version=" + azureMLValidationAPIVersion
	cmd := exec.Command("az", "rest", "--method", "get", "--url", url, "--output", "json")
	output, err := runProgressCommand("az rest ("+childPath+" validation context)", workingDir, env, progressWriter, cmd)
	if err != nil {
		return nil, fmt.Errorf("az rest failed for %s on %s: %s", childPath, workspaceID, strings.TrimSpace(string(output)))
	}
	response := azAutomationListResponse{}
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("parse az rest output for %s on %s: %w", childPath, workspaceID, err)
	}
	return response.Value, nil
}

func automationIdentityIDsFromAzure(accountID, identityType string, userAssigned map[string]any) []string {
	identityIDs := userAssignedIdentityIDs(userAssigned)
	if strings.Contains(strings.ToLower(strings.TrimSpace(identityType)), "systemassigned") && strings.TrimSpace(accountID) != "" {
		identityIDs = append(identityIDs, strings.TrimSpace(accountID)+"/identities/system")
	}
	sort.Strings(identityIDs)
	return slices.Compact(identityIDs)
}

func azureMLIdentityIDsFromAzure(workspaceID, identityType string, userAssigned map[string]any) []string {
	identityIDs := userAssignedIdentityIDs(userAssigned)
	if strings.Contains(strings.ToLower(strings.TrimSpace(identityType)), "systemassigned") && strings.TrimSpace(workspaceID) != "" {
		identityIDs = append(identityIDs, strings.TrimSpace(workspaceID)+"/identities/system")
	}
	sort.Strings(identityIDs)
	return slices.Compact(identityIDs)
}

func automationPublishedRunbookCountFromAzure(runbooks []map[string]any) int {
	count := 0
	for _, runbook := range runbooks {
		properties, _ := runbook["properties"].(map[string]any)
		state := strings.ToLower(strings.TrimSpace(firstNonEmptyString(stringValue(properties["state"]), stringValue(runbook["state"]))))
		if state == "published" {
			count++
		}
	}
	return count
}

func automationEncryptedVariableCountFromAzure(variables []map[string]any) int {
	count := 0
	for _, variable := range variables {
		properties, _ := variable["properties"].(map[string]any)
		if boolValue(properties["isEncrypted"]) || boolValue(variable["isEncrypted"]) {
			count++
		}
	}
	return count
}

func logicAppIdentityIDsFromAzure(workflowID, identityType string, userAssigned map[string]any) []string {
	identityIDs := userAssignedIdentityIDs(userAssigned)
	if strings.Contains(strings.ToLower(strings.TrimSpace(identityType)), "systemassigned") && strings.TrimSpace(workflowID) != "" {
		identityIDs = append(identityIDs, strings.TrimSpace(workflowID)+"/identities/system")
	}
	sort.Strings(identityIDs)
	return slices.Compact(identityIDs)
}

func logicAppDefinitionObject(definition map[string]any, key string) map[string]any {
	value, _ := definition[key].(map[string]any)
	return value
}

func logicAppTriggerTypesFromAzure(definition map[string]any) []string {
	triggers := logicAppDefinitionObject(definition, "triggers")
	triggerTypes := []string{}
	for _, rawTrigger := range triggers {
		trigger, ok := rawTrigger.(map[string]any)
		if !ok {
			continue
		}
		triggerType := strings.ToLower(strings.TrimSpace(stringValue(trigger["type"])))
		if triggerType == "" {
			continue
		}
		triggerTypes = append(triggerTypes, triggerType)
	}
	sort.Strings(triggerTypes)
	return slices.Compact(triggerTypes)
}

func logicAppHasRequestTriggerFromAzure(definition map[string]any) bool {
	triggers := logicAppDefinitionObject(definition, "triggers")
	for _, rawTrigger := range triggers {
		trigger, ok := rawTrigger.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(stringValue(trigger["type"]), "Request") {
			return true
		}
	}
	return false
}

func logicAppRecurrenceSummaryFromAzure(definition map[string]any) string {
	triggers := logicAppDefinitionObject(definition, "triggers")
	for _, rawTrigger := range triggers {
		trigger, ok := rawTrigger.(map[string]any)
		if !ok {
			continue
		}
		recurrence, _ := trigger["recurrence"].(map[string]any)
		if len(recurrence) == 0 && !strings.EqualFold(stringValue(trigger["type"]), "Recurrence") {
			continue
		}
		frequency := strings.TrimSpace(firstNonEmptyString(stringValue(recurrence["frequency"]), stringValue(trigger["frequency"])))
		interval := intValue(recurrence["interval"])
		if interval == 0 {
			interval = intValue(trigger["interval"])
		}
		if frequency == "" {
			frequency = "Recurring"
		}
		if interval > 0 {
			return fmt.Sprintf("%s/%d", frequency, interval)
		}
		return frequency
	}
	return ""
}

func logicAppDownstreamActionKindsFromAzure(definition map[string]any) []string {
	actions := []string{}
	logicAppWalkAzureActions(logicAppDefinitionObject(definition, "actions"), func(action map[string]any) {
		actionType := strings.ToLower(strings.TrimSpace(stringValue(action["type"])))
		payload := strings.ToLower(string(mustJSON(action)))
		switch {
		case actionType == "function" || strings.Contains(payload, "/functions/"):
			actions = append(actions, "function")
		case strings.Contains(payload, "microsoft.automation") || strings.Contains(payload, "automationaccounts"):
			actions = append(actions, "automation")
		case actionType == "http" || actionType == "httpwebhook":
			actions = append(actions, "external-http")
		case actionType == "apiconnection" || actionType == "apiconnectionwebhook":
			actions = append(actions, "connector")
		case strings.Contains(payload, "servicebus") || strings.Contains(payload, "eventhub") || strings.Contains(payload, "eventgrid"):
			actions = append(actions, "messaging")
		}
	})
	sort.Strings(actions)
	return slices.Compact(actions)
}

func logicAppWalkAzureActions(actions map[string]any, visit func(map[string]any)) {
	for _, rawAction := range actions {
		action, ok := rawAction.(map[string]any)
		if !ok {
			continue
		}
		visit(action)
		logicAppWalkAzureActions(logicAppDefinitionObject(action, "actions"), visit)
		if elseBlock, ok := action["else"].(map[string]any); ok {
			logicAppWalkAzureActions(logicAppDefinitionObject(elseBlock, "actions"), visit)
		}
		if cases, ok := action["cases"].(map[string]any); ok {
			for _, rawCase := range cases {
				caseBlock, ok := rawCase.(map[string]any)
				if !ok {
					continue
				}
				logicAppWalkAzureActions(logicAppDefinitionObject(caseBlock, "actions"), visit)
			}
		}
	}
}

func logicAppClassificationFromAzure(hasRequestTrigger, hasRecurrence, hasIdentity, hasDownstream bool) string {
	switch {
	case hasRequestTrigger || hasRecurrence:
		return "persistence-capable"
	case hasIdentity || hasDownstream:
		return "execution-capable-only"
	default:
		return "visibility-limited"
	}
}

func azureMLClassificationFromAzure(hasCompute, hasJobs, hasEndpoints, hasSchedules bool) string {
	switch {
	case hasCompute || hasJobs || hasEndpoints:
		return "execution-capable"
	case hasSchedules:
		return "supporting-persistence-context"
	default:
		return "supporting-context"
	}
}

func azureMLComputeTypesFromAzure(computes []map[string]any) []string {
	types := []string{}
	for _, compute := range computes {
		properties, _ := compute["properties"].(map[string]any)
		computeType := strings.TrimSpace(stringValue(properties["computeType"]))
		if computeType == "" {
			continue
		}
		types = append(types, computeType)
	}
	sort.Strings(types)
	return slices.Compact(types)
}

func azureMLJobTypesFromAzure(jobs []map[string]any) []string {
	types := []string{}
	for _, job := range jobs {
		properties, _ := job["properties"].(map[string]any)
		jobType := strings.TrimSpace(firstNonEmptyString(stringValue(properties["jobType"]), stringValue(job["kind"])))
		if jobType == "" {
			continue
		}
		types = append(types, jobType)
	}
	sort.Strings(types)
	return slices.Compact(types)
}

func azureMLScheduleTriggerTypesFromAzure(schedules []map[string]any) []string {
	types := []string{}
	for _, schedule := range schedules {
		properties, _ := schedule["properties"].(map[string]any)
		trigger, _ := properties["trigger"].(map[string]any)
		triggerType := strings.TrimSpace(stringValue(trigger["triggerType"]))
		if triggerType == "" {
			continue
		}
		types = append(types, triggerType)
	}
	sort.Strings(types)
	return slices.Compact(types)
}

func azureMLEndpointAuthModesFromAzure(endpoints []map[string]any) []string {
	values := []string{}
	for _, endpoint := range endpoints {
		properties, _ := endpoint["properties"].(map[string]any)
		authMode := strings.TrimSpace(stringValue(properties["authMode"]))
		if authMode == "" {
			continue
		}
		values = append(values, authMode)
	}
	sort.Strings(values)
	return slices.Compact(values)
}

func azureMLEndpointPublicAccessFromAzure(endpoints []map[string]any) []string {
	values := []string{}
	for _, endpoint := range endpoints {
		properties, _ := endpoint["properties"].(map[string]any)
		publicAccess := strings.TrimSpace(stringValue(properties["publicNetworkAccess"]))
		if publicAccess == "" {
			continue
		}
		values = append(values, publicAccess)
	}
	sort.Strings(values)
	return slices.Compact(values)
}

func azureMLDatastoreTypesFromAzure(datastores []map[string]any) []string {
	types := []string{}
	for _, datastore := range datastores {
		properties, _ := datastore["properties"].(map[string]any)
		datastoreType := strings.TrimSpace(stringValue(properties["datastoreType"]))
		if datastoreType == "" {
			continue
		}
		types = append(types, datastoreType)
	}
	sort.Strings(types)
	return slices.Compact(types)
}

func azureMLResourceIDsFromAzure(resources []map[string]any) []string {
	ids := []string{}
	for _, resource := range resources {
		resourceID := strings.TrimSpace(stringValue(resource["id"]))
		if resourceID == "" {
			continue
		}
		ids = append(ids, resourceID)
	}
	sort.Strings(ids)
	return slices.Compact(ids)
}

func azureMLRelatedIDsFromAzure(workspaceID string, identityIDs []string, storageAccountID string, keyVaultID string, containerRegistryID string, applicationInsightsID string, datastoreIDs []string) []string {
	values := []string{
		strings.TrimSpace(workspaceID),
		strings.TrimSpace(storageAccountID),
		strings.TrimSpace(keyVaultID),
		strings.TrimSpace(containerRegistryID),
		strings.TrimSpace(applicationInsightsID),
	}
	values = append(values, identityIDs...)
	values = append(values, datastoreIDs...)
	relatedIDs := []string{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		relatedIDs = append(relatedIDs, strings.TrimSpace(value))
	}
	sort.Strings(relatedIDs)
	return slices.Compact(relatedIDs)
}

func eventGridTruthFromAzure(route map[string]any) liveEventGridTruth {
	routeID := strings.TrimSpace(stringValue(route["id"]))
	properties := mapObjectValue(route, "properties")
	deliveryWithIdentity := mapObjectValue(properties, "deliveryWithResourceIdentity")
	destination := mapObjectValue(properties, "destination")
	if len(destination) == 0 {
		destination = mapObjectValue(deliveryWithIdentity, "destination")
	}

	destinationType := firstNonEmptyString(
		mapStringValue(destination, "endpointType", "endpoint_type"),
		mapStringValue(destination, "endpointtype"),
		"unknown",
	)
	destinationTargetID := eventGridDestinationTargetIDFromAzure(destination)
	identityType, identityID := eventGridIdentityContextFromAzure(deliveryWithIdentity, properties)
	sourceID := eventGridSourceIDFromAzure(routeID)
	return liveEventGridTruth{
		ID:                  firstNonEmptyString(routeID, "/unknown/event-grid-route"),
		Name:                firstNonEmptyString(stringValue(route["name"]), resourceNameFromID(routeID), "unknown"),
		Classification:      eventGridClassificationFromAzure(destinationType),
		SourceID:            sourceID,
		SourceType:          eventGridSourceTypeFromAzure(sourceID),
		DestinationType:     destinationType,
		DestinationTargetID: destinationTargetID,
		ExternalDelivery:    strings.EqualFold(destinationType, "WebHook"),
		ProvisioningState:   mapStringValue(properties, "provisioningState", "provisioning_state"),
		IdentityType:        identityType,
		IdentityID:          identityID,
		EventDeliverySchema: mapStringValue(properties, "eventDeliverySchema", "event_delivery_schema"),
		IncludedEventTypes:  eventGridIncludedEventTypesFromAzure(properties),
		RelatedIDs:          eventGridRelatedIDsFromAzure(sourceID, destinationTargetID, identityID),
	}
}

func eventGridDestinationTargetIDFromAzure(destination map[string]any) string {
	properties := mapObjectValue(destination, "properties")
	for _, key := range []string{"resourceId", "resource_id", "userAssignedIdentity", "user_assigned_identity"} {
		if value := mapStringValue(properties, key); value != "" {
			return value
		}
	}
	return mapStringValue(destination, "resourceId", "resource_id")
}

func eventGridIdentityContextFromAzure(deliveryWithIdentity map[string]any, properties map[string]any) (string, string) {
	identity := mapObjectValue(deliveryWithIdentity, "identity")
	if len(identity) == 0 {
		identity = mapObjectValue(properties, "identity")
	}
	if len(identity) == 0 {
		return "", ""
	}
	return mapStringValue(identity, "type"), firstNonEmptyString(
		mapStringValue(identity, "userAssignedIdentity", "user_assigned_identity"),
		mapStringValue(identity, "userAssignedIdentityResourceId", "user_assigned_identity_resource_id"),
	)
}

func eventGridIncludedEventTypesFromAzure(properties map[string]any) []string {
	filter := mapObjectValue(properties, "filter")
	values := listAnyValue(filter, "includedEventTypes", "included_event_types")
	if len(values) == 0 {
		return []string{"All"}
	}

	types := make([]string, 0, len(values))
	for _, value := range values {
		typed := strings.TrimSpace(stringValue(value))
		if typed == "" {
			continue
		}
		types = append(types, typed)
	}
	sort.Strings(types)
	return slices.Compact(types)
}

func eventGridSourceIDFromAzure(routeID string) string {
	const suffix = "/providers/Microsoft.EventGrid/eventSubscriptions/"
	index := strings.LastIndex(strings.ToLower(routeID), strings.ToLower(suffix))
	if index < 0 {
		return ""
	}
	return routeID[:index]
}

func eventGridSourceTypeFromAzure(sourceID string) string {
	parts := armIDParts(sourceID)
	if len(parts) == 0 {
		return ""
	}
	switch {
	case len(parts) == 2 && strings.EqualFold(parts[0], "subscriptions"):
		return "subscription"
	case len(parts) == 4 && strings.EqualFold(parts[2], "resourceGroups"):
		return "resource-group"
	}
	for index := 0; index < len(parts)-2; index++ {
		if strings.EqualFold(parts[index], "providers") {
			return parts[index+1] + "/" + parts[index+2]
		}
	}
	return ""
}

func eventGridClassificationFromAzure(destinationType string) string {
	switch {
	case strings.EqualFold(destinationType, "AzureFunction"), strings.EqualFold(destinationType, "HybridConnection"):
		return "execution-capable"
	case strings.EqualFold(destinationType, "WebHook"):
		return "external-callback"
	default:
		return "supporting-context"
	}
}

func eventGridRelatedIDsFromAzure(sourceID, destinationTargetID, identityID string) []string {
	values := []string{sourceID, destinationTargetID, identityID}
	relatedIDs := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		relatedIDs = append(relatedIDs, trimmed)
	}
	sort.Strings(relatedIDs)
	return slices.Compact(relatedIDs)
}

func armIDParts(resourceID string) []string {
	trimmed := strings.Trim(strings.TrimSpace(resourceID), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func resourceNameFromID(resourceID string) string {
	parts := armIDParts(resourceID)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func stringValue(value any) string {
	typed, _ := value.(string)
	return typed
}

func mapStringValue(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(stringValue(values[key]))
		if value != "" {
			return value
		}
	}
	return ""
}

func mapObjectValue(values map[string]any, key string) map[string]any {
	typed, _ := values[key].(map[string]any)
	return typed
}

func listAnyValue(values map[string]any, keys ...string) []any {
	for _, key := range keys {
		typed, ok := values[key].([]any)
		if ok {
			return typed
		}
	}
	return nil
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func boolValue(value any) bool {
	typed, _ := value.(bool)
	return typed
}

func intValuePtr(value int) *int {
	return &value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
