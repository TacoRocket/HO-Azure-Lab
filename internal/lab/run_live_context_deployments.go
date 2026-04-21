package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type liveArmDeploymentsContextArtifact struct {
	Deployments []liveArmDeploymentTruth `json:"deployments"`
}

type liveArmDeploymentTruth struct {
	ID                  string   `json:"id"`
	Mode                string   `json:"mode,omitempty"`
	Name                string   `json:"name"`
	OutputResourceCount int      `json:"output_resource_count"`
	OutputsCount        int      `json:"outputs_count"`
	ParametersLink      *string  `json:"parameters_link,omitempty"`
	Providers           []string `json:"providers"`
	ProvisioningState   string   `json:"provisioning_state,omitempty"`
	RelatedIDs          []string `json:"related_ids"`
	ResourceGroup       *string  `json:"resource_group,omitempty"`
	Scope               string   `json:"scope"`
	ScopeType           string   `json:"scope_type"`
	TemplateLink        *string  `json:"template_link,omitempty"`
}

type azDeploymentResource struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Properties azDeploymentProperties `json:"properties"`
}

type azDeploymentProperties struct {
	Mode              string                 `json:"mode"`
	Outputs           map[string]any         `json:"outputs"`
	OutputResources   []map[string]any       `json:"outputResources"`
	ParametersLink    azDeploymentLink       `json:"parametersLink"`
	Providers         []azDeploymentProvider `json:"providers"`
	ProvisioningState string                 `json:"provisioningState"`
	TemplateLink      azDeploymentLink       `json:"templateLink"`
}

type azDeploymentLink struct {
	URI string `json:"uri"`
}

type azDeploymentProvider struct {
	Namespace string `json:"namespace"`
}

type azResourceGroupListResource struct {
	Name string `json:"name"`
}

func captureLiveArmDeploymentsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	subscriptionCmd := exec.Command("az", "deployment", "sub", "list", "--output", "json")
	subscriptionOutput, err := runProgressCommand("az deployment sub list (arm-deployments validation context)", workingDir, env, progressWriter, subscriptionCmd)
	if err != nil {
		return fmt.Errorf("az deployment sub list failed: %s", strings.TrimSpace(string(subscriptionOutput)))
	}
	subscriptionDeployments := []azDeploymentResource{}
	if err := json.Unmarshal(subscriptionOutput, &subscriptionDeployments); err != nil {
		return fmt.Errorf("parse subscription deployment list output: %w", err)
	}

	groupCmd := exec.Command("az", "group", "list", "--output", "json")
	groupOutput, err := runProgressCommand("az group list (arm-deployments validation context)", workingDir, env, progressWriter, groupCmd)
	if err != nil {
		return fmt.Errorf("az group list failed: %s", strings.TrimSpace(string(groupOutput)))
	}
	resourceGroups := []azResourceGroupListResource{}
	if err := json.Unmarshal(groupOutput, &resourceGroups); err != nil {
		return fmt.Errorf("parse resource group list output: %w", err)
	}

	truthByID := map[string]liveArmDeploymentTruth{}
	for _, deployment := range subscriptionDeployments {
		truth := deploymentTruthFromAzure(deployment, "subscription", "")
		if strings.TrimSpace(truth.ID) == "" {
			continue
		}
		truthByID[normalizeResourceID(truth.ID)] = truth
	}

	for _, resourceGroup := range resourceGroups {
		name := strings.TrimSpace(resourceGroup.Name)
		if name == "" {
			continue
		}
		groupListCmd := exec.Command("az", "deployment", "group", "list", "--resource-group", name, "--output", "json")
		label := fmt.Sprintf("az deployment group list (arm-deployments validation context: %s)", name)
		groupListOutput, err := runProgressCommand(label, workingDir, env, progressWriter, groupListCmd)
		if err != nil {
			return fmt.Errorf("az deployment group list failed for %q: %s", name, strings.TrimSpace(string(groupListOutput)))
		}
		groupDeployments := []azDeploymentResource{}
		if err := json.Unmarshal(groupListOutput, &groupDeployments); err != nil {
			return fmt.Errorf("parse resource-group deployment list output for %q: %w", name, err)
		}
		for _, deployment := range groupDeployments {
			truth := deploymentTruthFromAzure(deployment, "resource_group", name)
			if strings.TrimSpace(truth.ID) == "" {
				continue
			}
			truthByID[normalizeResourceID(truth.ID)] = truth
		}
	}

	truths := make([]liveArmDeploymentTruth, 0, len(truthByID))
	for _, truth := range truthByID {
		truths = append(truths, truth)
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return normalizeResourceID(truths[i].ID) < normalizeResourceID(truths[j].ID)
	})

	artifact := liveArmDeploymentsContextArtifact{Deployments: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-arm-deployments-context.json"), artifact); err != nil {
		return fmt.Errorf("write live arm-deployments context artifact: %w", err)
	}
	return nil
}

func deploymentTruthFromAzure(deployment azDeploymentResource, scopeType, resourceGroup string) liveArmDeploymentTruth {
	deploymentID := strings.TrimSpace(deployment.ID)
	resourceGroupValue := strings.TrimSpace(resourceGroup)
	if resourceGroupValue == "" {
		resourceGroupValue = resourceGroupFromAzureID(deploymentID)
	}
	scope := deploymentScopeFromID(deploymentID)

	truth := liveArmDeploymentTruth{
		ID:                  deploymentID,
		Mode:                strings.TrimSpace(deployment.Properties.Mode),
		Name:                firstNonEmpty(strings.TrimSpace(deployment.Name), resourceNameFromAzureID(deploymentID)),
		OutputResourceCount: len(deployment.Properties.OutputResources),
		OutputsCount:        len(deployment.Properties.Outputs),
		ParametersLink:      stringPtr(strings.TrimSpace(deployment.Properties.ParametersLink.URI)),
		Providers:           deploymentProvidersFromAzure(deployment.Properties.Providers),
		ProvisioningState:   strings.TrimSpace(deployment.Properties.ProvisioningState),
		RelatedIDs:          []string{deploymentID},
		Scope:               scope,
		ScopeType:           scopeType,
		TemplateLink:        stringPtr(strings.TrimSpace(deployment.Properties.TemplateLink.URI)),
	}
	if resourceGroupValue != "" {
		truth.ResourceGroup = stringPtr(resourceGroupValue)
	}
	return truth
}

func deploymentScopeFromID(deploymentID string) string {
	value := strings.TrimSpace(deploymentID)
	if value == "" {
		return ""
	}
	marker := strings.Index(strings.ToLower(value), "/providers/microsoft.resources/deployments/")
	if marker == -1 {
		return ""
	}
	return strings.TrimSpace(value[:marker])
}

func deploymentProvidersFromAzure(providers []azDeploymentProvider) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, provider := range providers {
		namespace := strings.TrimSpace(provider.Namespace)
		if namespace == "" {
			continue
		}
		key := strings.ToLower(namespace)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, namespace)
	}
	sort.Strings(values)
	return values
}
