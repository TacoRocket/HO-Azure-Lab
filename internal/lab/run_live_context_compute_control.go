package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

type liveComputeControlContextArtifact struct {
	ExpectZeroRows          bool                         `json:"expect_zero_rows"`
	ZeroRowReason           string                       `json:"zero_row_reason,omitempty"`
	RequiredIssueCollectors []string                     `json:"required_issue_collectors,omitempty"`
	Canary                  *liveComputeControlCanaryRow `json:"canary,omitempty"`
}

type liveComputeControlCanaryRow struct {
	AssetID             string   `json:"asset_id"`
	AssetName           string   `json:"asset_name"`
	AssetKind           string   `json:"asset_kind"`
	IdentityID          string   `json:"identity_id"`
	IdentityName        string   `json:"identity_name"`
	IdentityType        string   `json:"identity_type"`
	TargetResolution    string   `json:"target_resolution"`
	RequiredEvidence    []string `json:"required_evidence"`
	PublicNetworkAccess string   `json:"public_network_access,omitempty"`
}

type azRoleAssignmentEntry struct {
	ID                 string `json:"id"`
	RoleDefinitionName string `json:"roleDefinitionName"`
	Scope              string `json:"scope"`
}

func captureLiveComputeControlContext(outdir, infraDir, workingDir string, env []string, progressWriter io.Writer) error {
	outputs, err := loadTofuOutputs(infraDir, "tofu")
	if err != nil {
		return fmt.Errorf("load tofu outputs for compute-control context: %w", err)
	}

	appName, err := outputNestedString(outputs, "compute_control_addin", "app_name")
	if err != nil {
		return fmt.Errorf("load compute-control add-in app name: %w", err)
	}
	identityID, err := outputNestedString(outputs, "managed_identity", "id")
	if err != nil {
		return fmt.Errorf("load managed identity id for compute-control context: %w", err)
	}
	identityName, err := outputNestedString(outputs, "managed_identity", "name")
	if err != nil {
		return fmt.Errorf("load managed identity name for compute-control context: %w", err)
	}
	identityPrincipalID, err := outputNestedString(outputs, "managed_identity", "principal_id")
	if err != nil {
		return fmt.Errorf("load managed identity principal id for compute-control context: %w", err)
	}
	identityOwnerScope, err := outputNestedString(outputs, "managed_identity", "owner_scope")
	if err != nil {
		return fmt.Errorf("load managed identity owner scope for compute-control context: %w", err)
	}
	resourceGroups, err := outputStringMap(outputs, "resource_group_names")
	if err != nil {
		return fmt.Errorf("load resource group names for compute-control context: %w", err)
	}
	workloadRG := strings.TrimSpace(resourceGroups["workload"])
	if workloadRG == "" {
		return fmt.Errorf("compute-control context did not find a workload resource group in tofu outputs")
	}

	artifact := liveComputeControlContextArtifact{}
	blockedEnvVarCollector := fmt.Sprintf("env_vars[%s/%s]", workloadRG, appName)

	webAppCmd := exec.Command("az", "webapp", "show", "--resource-group", workloadRG, "--name", appName, "--output", "json")
	webAppOutput, err := runProgressCommand("az webapp show (compute-control validation context)", workingDir, env, progressWriter, webAppCmd)
	if err != nil {
		if computeControlVisibilityDenied(webAppOutput) {
			artifact.ExpectZeroRows = true
			artifact.ZeroRowReason = "visibility_blocked"
			artifact.RequiredIssueCollectors = []string{blockedEnvVarCollector}
			return WriteJSON(filepath.Join(outdir, "live-compute-control-context.json"), artifact)
		}
		return fmt.Errorf("az webapp show failed: %s", strings.TrimSpace(string(webAppOutput)))
	}

	webApp := azAppServiceResource{}
	if err := json.Unmarshal(webAppOutput, &webApp); err != nil {
		return fmt.Errorf("parse az webapp show output: %w", err)
	}
	identityIDs := appServiceIdentityIDs(webApp)
	if !slicesContainsNormalized(identityIDs, identityID) {
		return fmt.Errorf("compute-control add-in app service %q does not currently expose expected managed identity %q", appName, identityID)
	}

	roleAssignmentsCmd := exec.Command(
		"az", "role", "assignment", "list",
		"--assignee-object-id", identityPrincipalID,
		"--scope", identityOwnerScope,
		"--output", "json",
	)
	roleAssignmentsOutput, err := runProgressCommand("az role assignment list (compute-control validation context)", workingDir, env, progressWriter, roleAssignmentsCmd)
	if err != nil {
		if computeControlVisibilityDenied(roleAssignmentsOutput) {
			artifact.ExpectZeroRows = true
			artifact.ZeroRowReason = "visibility_blocked"
			return WriteJSON(filepath.Join(outdir, "live-compute-control-context.json"), artifact)
		}
		return fmt.Errorf("az role assignment list failed: %s", strings.TrimSpace(string(roleAssignmentsOutput)))
	}

	assignments := []azRoleAssignmentEntry{}
	if err := json.Unmarshal(roleAssignmentsOutput, &assignments); err != nil {
		return fmt.Errorf("parse az role assignment list output: %w", err)
	}
	if len(assignments) == 0 {
		artifact.ExpectZeroRows = true
		artifact.ZeroRowReason = "no_visible_control_path"
		return WriteJSON(filepath.Join(outdir, "live-compute-control-context.json"), artifact)
	}

	artifact.Canary = &liveComputeControlCanaryRow{
		AssetID:             strings.TrimSpace(webApp.ID),
		AssetName:           strings.TrimSpace(webApp.Name),
		AssetKind:           "AppService",
		IdentityID:          identityID,
		IdentityName:        identityName,
		IdentityType:        strings.TrimSpace(webApp.Identity.Type),
		TargetResolution:    "path-confirmed",
		RequiredEvidence:    []string{"tokens-credentials", "workloads", "managed-identities", "permissions"},
		PublicNetworkAccess: firstNonEmpty(strings.TrimSpace(webApp.PublicNetworkAccess), strings.TrimSpace(webApp.Properties.PublicNetworkAccess)),
	}
	return WriteJSON(filepath.Join(outdir, "live-compute-control-context.json"), artifact)
}

func computeControlVisibilityDenied(output []byte) bool {
	lowered := strings.ToLower(string(output))
	return strings.Contains(lowered, "authorizationfailed") ||
		strings.Contains(lowered, "insufficient privileges") ||
		strings.Contains(lowered, "does not have authorization")
}

func slicesContainsNormalized(values []string, target string) bool {
	normalizedTarget := normalizeResourceID(target)
	for _, value := range values {
		if normalizeResourceID(value) == normalizedTarget {
			return true
		}
	}
	return false
}
