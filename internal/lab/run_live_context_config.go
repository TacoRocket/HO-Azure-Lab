package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type liveEnvVarsContextArtifact struct {
	Assets  []liveEnvVarAssetTruth `json:"assets"`
	EnvVars []liveEnvVarTruth      `json:"env_vars"`
}

type liveEnvVarAssetTruth struct {
	AssetID                   string   `json:"asset_id"`
	AssetKind                 string   `json:"asset_kind"`
	AssetName                 string   `json:"asset_name"`
	KeyVaultReferenceIdentity *string  `json:"key_vault_reference_identity,omitempty"`
	Location                  string   `json:"location"`
	ResourceGroup             string   `json:"resource_group"`
	SettingsReadable          bool     `json:"settings_readable"`
	WorkloadIdentityIDs       []string `json:"workload_identity_ids,omitempty"`
	WorkloadIdentityType      *string  `json:"workload_identity_type,omitempty"`
	WorkloadPrincipalID       *string  `json:"workload_principal_id,omitempty"`
}

type liveEnvVarTruth struct {
	AssetID                   string   `json:"asset_id"`
	AssetKind                 string   `json:"asset_kind"`
	AssetName                 string   `json:"asset_name"`
	KeyVaultReferenceIdentity *string  `json:"key_vault_reference_identity,omitempty"`
	Location                  string   `json:"location"`
	LooksSensitive            bool     `json:"looks_sensitive"`
	ReferenceTarget           *string  `json:"reference_target,omitempty"`
	ResourceGroup             string   `json:"resource_group"`
	SettingName               string   `json:"setting_name"`
	ValueType                 string   `json:"value_type"`
	WorkloadIdentityIDs       []string `json:"workload_identity_ids,omitempty"`
	WorkloadIdentityType      *string  `json:"workload_identity_type,omitempty"`
	WorkloadPrincipalID       *string  `json:"workload_principal_id,omitempty"`
}

type azWebSiteListResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Location      string `json:"location"`
	ResourceGroup string `json:"resourceGroup"`
}

type azWebSiteShowResource struct {
	ID                        string `json:"id"`
	Name                      string `json:"name"`
	Kind                      string `json:"kind"`
	Location                  string `json:"location"`
	KeyVaultReferenceIdentity string `json:"keyVaultReferenceIdentity"`
	Identity                  struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	Properties struct {
		KeyVaultReferenceIdentity string `json:"keyVaultReferenceIdentity"`
	} `json:"properties"`
}

type azAppSettingRecord struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func captureLiveEnvVarsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	resourceCmd := exec.Command(
		"az", "resource", "list",
		"--resource-type", "Microsoft.Web/sites",
		"--query", "[].{id:id,name:name,kind:kind,location:location,resourceGroup:resourceGroup}",
		"--output", "json",
	)
	resourceOutput, err := runProgressCommand("az resource list (env-vars validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for env-vars validation context: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azWebSiteListResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse env-vars resource list output: %w", err)
	}

	assets := []liveEnvVarAssetTruth{}
	rows := []liveEnvVarTruth{}
	for _, resource := range resources {
		assetKind := workloadAssetKind("Microsoft.Web/sites", resource.Kind)
		if assetKind == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", resource.ID, "--output", "json")
		showLabel := fmt.Sprintf("az resource show (env-vars validation context: %s)", resource.Name)
		showOutput, err := runProgressCommand(showLabel, workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %q: %s", resource.ID, strings.TrimSpace(string(showOutput)))
		}
		detail := azWebSiteShowResource{}
		if err := json.Unmarshal(showOutput, &detail); err != nil {
			return fmt.Errorf("parse env-vars resource detail for %q: %w", resource.ID, err)
		}

		asset := liveEnvVarAssetTruth{
			AssetID:                   resource.ID,
			AssetKind:                 assetKind,
			AssetName:                 firstNonEmpty(resource.Name, detail.Name),
			KeyVaultReferenceIdentity: stringPtr(firstNonEmpty(detail.KeyVaultReferenceIdentity, detail.Properties.KeyVaultReferenceIdentity)),
			Location:                  firstNonEmpty(resource.Location, detail.Location),
			ResourceGroup:             firstNonEmpty(resource.ResourceGroup, resourceGroupFromAzureID(resource.ID)),
			SettingsReadable:          true,
			WorkloadIdentityIDs:       userAssignedIdentityIDs(detail.Identity.UserAssignedIdentities),
			WorkloadIdentityType:      stringPtr(detail.Identity.Type),
			WorkloadPrincipalID:       stringPtr(detail.Identity.PrincipalID),
		}

		settingCmd := envVarAppSettingsCommand(assetKind, resource.ResourceGroup, resource.Name)
		settingLabel := fmt.Sprintf("%s (env-vars validation context: %s)", strings.Join(settingCmd.Args[:4], " "), resource.Name)
		settingOutput, err := runProgressCommand(settingLabel, workingDir, env, progressWriter, settingCmd)
		if err != nil {
			if envVarSettingsReadDenied(settingOutput) {
				asset.SettingsReadable = false
				assets = append(assets, asset)
				continue
			}
			return fmt.Errorf("list env-vars settings for %q: %s", resource.ID, strings.TrimSpace(string(settingOutput)))
		}
		assets = append(assets, asset)
		settings := []azAppSettingRecord{}
		if err := json.Unmarshal(settingOutput, &settings); err != nil {
			return fmt.Errorf("parse env-vars settings for %q: %w", resource.ID, err)
		}

		for _, setting := range settings {
			valueType := envVarContextValueType(setting.Value)
			rows = append(rows, liveEnvVarTruth{
				AssetID:                   asset.AssetID,
				AssetKind:                 asset.AssetKind,
				AssetName:                 asset.AssetName,
				KeyVaultReferenceIdentity: asset.KeyVaultReferenceIdentity,
				Location:                  asset.Location,
				LooksSensitive:            envVarContextLooksSensitiveSettingName(setting.Name),
				ReferenceTarget:           stringPtr(envVarContextReferenceTarget(setting.Value)),
				ResourceGroup:             asset.ResourceGroup,
				SettingName:               setting.Name,
				ValueType:                 valueType,
				WorkloadIdentityIDs:       append([]string{}, asset.WorkloadIdentityIDs...),
				WorkloadIdentityType:      asset.WorkloadIdentityType,
				WorkloadPrincipalID:       asset.WorkloadPrincipalID,
			})
		}
	}

	sort.SliceStable(assets, func(i, j int) bool {
		return normalizeResourceID(assets[i].AssetID) < normalizeResourceID(assets[j].AssetID)
	})
	sort.SliceStable(rows, func(i, j int) bool {
		left := normalizeResourceID(rows[i].AssetID) + "|" + strings.ToLower(strings.TrimSpace(rows[i].SettingName))
		right := normalizeResourceID(rows[j].AssetID) + "|" + strings.ToLower(strings.TrimSpace(rows[j].SettingName))
		return left < right
	})

	artifact := liveEnvVarsContextArtifact{
		Assets:  assets,
		EnvVars: rows,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-env-vars-context.json"), artifact); err != nil {
		return fmt.Errorf("write live env-vars context artifact: %w", err)
	}
	return nil
}

func envVarAppSettingsCommand(assetKind, resourceGroup, name string) *exec.Cmd {
	if assetKind == "FunctionApp" {
		return exec.Command("az", "functionapp", "config", "appsettings", "list", "--resource-group", resourceGroup, "--name", name, "--output", "json")
	}
	return exec.Command("az", "webapp", "config", "appsettings", "list", "--resource-group", resourceGroup, "--name", name, "--output", "json")
}

func envVarContextValueType(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return "empty"
	}
	if strings.HasPrefix(text, "@Microsoft.KeyVault(") {
		return "keyvault-ref"
	}
	return "plain-text"
}

func envVarContextLooksSensitiveSettingName(settingName string) bool {
	normalized := strings.ToLower(settingName)
	replacer := strings.NewReplacer("-", "", "_", "", ".", "", " ", "")
	normalized = replacer.Replace(normalized)
	for _, token := range []string{"key", "secret", "token", "password", "passwd", "connectionstring", "connstr", "clientsecret"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func envVarContextReferenceTarget(value string) string {
	text := strings.TrimSpace(value)
	if !strings.HasPrefix(text, "@Microsoft.KeyVault(") {
		return ""
	}
	if match := regexp.MustCompile(`SecretUri=([^)]+)`).FindStringSubmatch(text); len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	vaultName := envVarContextReferencePart(text, "VaultName")
	secretName := envVarContextReferencePart(text, "SecretName")
	secretVersion := envVarContextReferencePart(text, "SecretVersion")
	if vaultName == "" || secretName == "" {
		return ""
	}
	target := strings.TrimSpace(vaultName) + ".vault.azure.net/secrets/" + strings.TrimSpace(secretName)
	if strings.TrimSpace(secretVersion) != "" {
		target += "/" + strings.TrimSpace(secretVersion)
	}
	return target
}

func envVarContextReferencePart(text, key string) string {
	match := regexp.MustCompile(key + `=([^;)]*)`).FindStringSubmatch(text)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func envVarSettingsReadDenied(output []byte) bool {
	lowered := strings.ToLower(string(output))
	return strings.Contains(lowered, "authorizationfailed") &&
		strings.Contains(lowered, "microsoft.web/sites/config/list/action")
}

func stringPtr(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
