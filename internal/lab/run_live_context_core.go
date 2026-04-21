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

type liveInventoryContextArtifact struct {
	TenantID           string         `json:"tenant_id,omitempty"`
	Subscription       inventoryTruth `json:"subscription"`
	ResourceCount      int            `json:"resource_count"`
	ResourceGroupCount int            `json:"resource_group_count"`
	TopResourceTypes   map[string]int `json:"top_resource_types"`
}

type inventoryTruth struct {
	DisplayName string `json:"display_name,omitempty"`
	ID          string `json:"id"`
	State       string `json:"state,omitempty"`
}

type azAccountShowResult struct {
	TenantID     string `json:"tenantId"`
	Name         string `json:"name"`
	ID           string `json:"id"`
	State        string `json:"state"`
	DisplayName  string `json:"displayName"`
	Subscription string `json:"subscription"`
}

type azResourceGroupListItem struct {
	ID string `json:"id"`
}

type azResourceListItem struct {
	Type string `json:"type"`
}

func captureLiveInventoryContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	accountCmd := exec.Command("az", "account", "show", "--output", "json")
	accountOutput, err := runProgressCommand("az account show (inventory validation context)", workingDir, env, progressWriter, accountCmd)
	if err != nil {
		return fmt.Errorf("az account show failed: %s", strings.TrimSpace(string(accountOutput)))
	}
	account := azAccountShowResult{}
	if err := json.Unmarshal(accountOutput, &account); err != nil {
		return fmt.Errorf("parse az account show output: %w", err)
	}

	groupCmd := exec.Command("az", "group", "list", "--output", "json")
	groupOutput, err := runProgressCommand("az group list (inventory validation context)", workingDir, env, progressWriter, groupCmd)
	if err != nil {
		return fmt.Errorf("az group list failed: %s", strings.TrimSpace(string(groupOutput)))
	}
	resourceGroups := []azResourceGroupListItem{}
	if err := json.Unmarshal(groupOutput, &resourceGroups); err != nil {
		return fmt.Errorf("parse az group list output: %w", err)
	}

	resourceCmd := exec.Command("az", "resource", "list", "--output", "json")
	resourceOutput, err := runProgressCommand("az resource list (inventory validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azResourceListItem{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az resource list output: %w", err)
	}

	topTypes := map[string]int{}
	for _, resource := range resources {
		resourceType := strings.TrimSpace(resource.Type)
		if resourceType == "" {
			continue
		}
		topTypes[resourceType]++
	}

	sortedTopTypes := map[string]int{}
	keys := make([]string, 0, len(topTypes))
	for key := range topTypes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sortedTopTypes[key] = topTypes[key]
	}

	artifact := liveInventoryContextArtifact{
		TenantID: strings.TrimSpace(account.TenantID),
		Subscription: inventoryTruth{
			DisplayName: firstNonEmpty(strings.TrimSpace(account.DisplayName), strings.TrimSpace(account.Name)),
			ID:          firstNonEmpty(strings.TrimSpace(account.Subscription), strings.TrimSpace(account.ID)),
			State:       strings.TrimSpace(account.State),
		},
		ResourceCount:      len(resources),
		ResourceGroupCount: len(resourceGroups),
		TopResourceTypes:   sortedTopTypes,
	}

	if err := WriteJSON(filepath.Join(outdir, "live-inventory-context.json"), artifact); err != nil {
		return fmt.Errorf("write live inventory context artifact: %w", err)
	}
	return nil
}
