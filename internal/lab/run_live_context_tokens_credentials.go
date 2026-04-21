package lab

import (
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type liveTokensCredentialsContextArtifact struct {
	ExpectedSurfaces      []liveTokensCredentialSurfaceTruth      `json:"expected_surfaces"`
	BlockedAppSettingRead []liveTokensCredentialBlockedAssetTruth `json:"blocked_app_setting_read"`
}

type liveTokensCredentialSurfaceTruth struct {
	AccessPath     string `json:"access_path"`
	AssetID        string `json:"asset_id"`
	AssetKind      string `json:"asset_kind"`
	AssetName      string `json:"asset_name"`
	OperatorSignal string `json:"operator_signal"`
	Priority       string `json:"priority"`
	SurfaceType    string `json:"surface_type"`
}

type liveTokensCredentialBlockedAssetTruth struct {
	AssetID   string `json:"asset_id"`
	AssetName string `json:"asset_name"`
	Scope     string `json:"scope"`
}

func captureLiveTokensCredentialsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	captures := []struct {
		name string
		fn   func(string, string, []string, io.Writer) error
	}{
		{name: "app-services", fn: captureLiveAppServicesContext},
		{name: "functions", fn: captureLiveFunctionsContext},
		{name: "container-apps", fn: captureLiveContainerAppsContext},
		{name: "container-instances", fn: captureLiveContainerInstancesContext},
		{name: "env-vars", fn: captureLiveEnvVarsContext},
		{name: "arm-deployments", fn: captureLiveArmDeploymentsContext},
		{name: "vms", fn: captureLiveVMSContext},
		{name: "vmss", fn: captureLiveVMSSContext},
	}
	for _, capture := range captures {
		if err := capture.fn(outdir, workingDir, env, progressWriter); err != nil {
			return fmt.Errorf("capture %s context for tokens-credentials: %w", capture.name, err)
		}
	}

	appServices := liveAppServicesContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-app-services-context.json"), &appServices); err != nil {
		return fmt.Errorf("load live app-services context: %w", err)
	}
	functions := liveFunctionsContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-functions-context.json"), &functions); err != nil {
		return fmt.Errorf("load live functions context: %w", err)
	}
	containerApps := liveContainerAppsContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-container-apps-context.json"), &containerApps); err != nil {
		return fmt.Errorf("load live container-apps context: %w", err)
	}
	containerInstances := liveContainerInstancesContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-container-instances-context.json"), &containerInstances); err != nil {
		return fmt.Errorf("load live container-instances context: %w", err)
	}
	envVars := liveEnvVarsContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-env-vars-context.json"), &envVars); err != nil {
		return fmt.Errorf("load live env-vars context: %w", err)
	}
	deployments := liveArmDeploymentsContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-arm-deployments-context.json"), &deployments); err != nil {
		return fmt.Errorf("load live arm-deployments context: %w", err)
	}
	vms := liveVMSContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-vms-context.json"), &vms); err != nil {
		return fmt.Errorf("load live vms context: %w", err)
	}
	vmss := liveVMSSContextArtifact{}
	if err := LoadJSON(filepath.Join(outdir, "live-vmss-context.json"), &vmss); err != nil {
		return fmt.Errorf("load live vmss context: %w", err)
	}

	artifact := liveTokensCredentialsContextArtifact{}
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveEnvVars(envVars)...)
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveDeployments(deployments)...)
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveAppServices(appServices)...)
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveFunctions(functions)...)
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveContainerApps(containerApps)...)
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveContainerInstances(containerInstances)...)
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveVMs(vms)...)
	artifact.ExpectedSurfaces = append(artifact.ExpectedSurfaces, tokenCredentialSurfacesFromLiveVMSS(vmss)...)
	artifact.BlockedAppSettingRead = blockedTokenCredentialAssetsFromLiveEnvVars(envVars)

	sort.SliceStable(artifact.ExpectedSurfaces, func(i, j int) bool {
		left := normalizeResourceID(artifact.ExpectedSurfaces[i].AssetID) + "|" + artifact.ExpectedSurfaces[i].SurfaceType + "|" + artifact.ExpectedSurfaces[i].AccessPath + "|" + strings.ToLower(strings.TrimSpace(artifact.ExpectedSurfaces[i].OperatorSignal))
		right := normalizeResourceID(artifact.ExpectedSurfaces[j].AssetID) + "|" + artifact.ExpectedSurfaces[j].SurfaceType + "|" + artifact.ExpectedSurfaces[j].AccessPath + "|" + strings.ToLower(strings.TrimSpace(artifact.ExpectedSurfaces[j].OperatorSignal))
		return left < right
	})
	sort.SliceStable(artifact.BlockedAppSettingRead, func(i, j int) bool {
		return normalizeResourceID(artifact.BlockedAppSettingRead[i].AssetID) < normalizeResourceID(artifact.BlockedAppSettingRead[j].AssetID)
	})

	if err := WriteJSON(filepath.Join(outdir, "live-tokens-credentials-context.json"), artifact); err != nil {
		return fmt.Errorf("write live tokens-credentials context artifact: %w", err)
	}
	return nil
}

func tokenCredentialSurfacesFromLiveAppServices(context liveAppServicesContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := make([]liveTokensCredentialSurfaceTruth, 0, len(context.AppServices))
	for _, truth := range context.AppServices {
		surface, ok := tokenCredentialManagedIdentitySurfaceTruth(truth.ID, "AppService", truth.Name, truth.IdentityType, truth.IdentityIDs, "workload-identity")
		if !ok {
			continue
		}
		surfaces = append(surfaces, surface)
	}
	return surfaces
}

func tokenCredentialSurfacesFromLiveFunctions(context liveFunctionsContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := make([]liveTokensCredentialSurfaceTruth, 0, len(context.FunctionApps))
	for _, truth := range context.FunctionApps {
		surface, ok := tokenCredentialManagedIdentitySurfaceTruth(truth.ID, "FunctionApp", truth.Name, truth.IdentityType, truth.IdentityIDs, "workload-identity")
		if !ok {
			continue
		}
		surfaces = append(surfaces, surface)
	}
	return surfaces
}

func tokenCredentialSurfacesFromLiveContainerApps(context liveContainerAppsContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := make([]liveTokensCredentialSurfaceTruth, 0, len(context.ContainerApps))
	for _, truth := range context.ContainerApps {
		surface, ok := tokenCredentialManagedIdentitySurfaceTruth(truth.ID, "ContainerApp", truth.Name, truth.IdentityType, truth.IdentityIDs, "workload-identity")
		if !ok {
			continue
		}
		surfaces = append(surfaces, surface)
	}
	return surfaces
}

func tokenCredentialSurfacesFromLiveContainerInstances(context liveContainerInstancesContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := make([]liveTokensCredentialSurfaceTruth, 0, len(context.ContainerInstances))
	for _, truth := range context.ContainerInstances {
		surface, ok := tokenCredentialManagedIdentitySurfaceTruth(truth.ID, "ContainerInstance", truth.Name, truth.IdentityType, truth.IdentityIDs, "workload-identity")
		if !ok {
			continue
		}
		surfaces = append(surfaces, surface)
	}
	return surfaces
}

func tokenCredentialManagedIdentitySurfaceTruth(assetID, assetKind, assetName, identityType string, identityIDs []string, accessPath string) (liveTokensCredentialSurfaceTruth, bool) {
	identityLabel := strings.TrimSpace(identityType)
	if identityLabel == "" {
		return liveTokensCredentialSurfaceTruth{}, false
	}
	operatorSignal := identityLabel
	if len(identityIDs) > 0 {
		operatorSignal += "; user-assigned=" + strconv.Itoa(len(identityIDs))
	}
	return liveTokensCredentialSurfaceTruth{
		AccessPath:     accessPath,
		AssetID:        assetID,
		AssetKind:      assetKind,
		AssetName:      assetName,
		OperatorSignal: operatorSignal,
		Priority:       "medium",
		SurfaceType:    "managed-identity-token",
	}, true
}

func blockedTokenCredentialAssetsFromLiveEnvVars(context liveEnvVarsContextArtifact) []liveTokensCredentialBlockedAssetTruth {
	blocked := []liveTokensCredentialBlockedAssetTruth{}
	for _, asset := range context.Assets {
		if asset.SettingsReadable {
			continue
		}
		blocked = append(blocked, liveTokensCredentialBlockedAssetTruth{
			AssetID:   asset.AssetID,
			AssetName: asset.AssetName,
			Scope:     envVarIssueScope(asset),
		})
	}
	return blocked
}

func tokenCredentialSurfacesFromLiveEnvVars(context liveEnvVarsContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := []liveTokensCredentialSurfaceTruth{}
	for _, truth := range context.EnvVars {
		if tokenCredentialPlainTextSettingExpected(truth) {
			surfaces = append(surfaces, liveTokensCredentialSurfaceTruth{
				AccessPath:     "app-setting",
				AssetID:        truth.AssetID,
				AssetKind:      truth.AssetKind,
				AssetName:      truth.AssetName,
				OperatorSignal: "setting=" + truth.SettingName,
				Priority:       "high",
				SurfaceType:    "plain-text-secret",
			})
		}
		if truth.ValueType == "keyvault-ref" {
			signalParts := []string{"target=" + valueOrUnknownLab(stringPtrValueLab(truth.ReferenceTarget))}
			identitySummary := keyVaultReferenceIdentitySummaryLab(stringPtrValueLab(truth.KeyVaultReferenceIdentity))
			if identitySummary != "" {
				signalParts = append(signalParts, "identity="+identitySummary)
			}
			surfaces = append(surfaces, liveTokensCredentialSurfaceTruth{
				AccessPath:     "app-setting",
				AssetID:        truth.AssetID,
				AssetKind:      truth.AssetKind,
				AssetName:      truth.AssetName,
				OperatorSignal: strings.Join(signalParts, "; "),
				Priority:       "medium",
				SurfaceType:    "keyvault-reference",
			})
		}
	}
	return surfaces
}

func tokenCredentialPlainTextSettingExpected(truth liveEnvVarTruth) bool {
	if truth.ValueType != "plain-text" {
		return false
	}
	if truth.LooksSensitive {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(truth.AssetKind), "FunctionApp") &&
		strings.EqualFold(strings.TrimSpace(truth.SettingName), "AzureWebJobsStorage")
}

func tokenCredentialSurfacesFromLiveDeployments(context liveArmDeploymentsContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := []liveTokensCredentialSurfaceTruth{}
	for _, truth := range context.Deployments {
		if truth.OutputsCount > 0 {
			surfaces = append(surfaces, liveTokensCredentialSurfaceTruth{
				AccessPath:     "deployment-history",
				AssetID:        truth.ID,
				AssetKind:      "ArmDeployment",
				AssetName:      truth.Name,
				OperatorSignal: "outputs=" + strconv.Itoa(truth.OutputsCount) + "; providers=" + strconv.Itoa(len(truth.Providers)),
				Priority:       "medium",
				SurfaceType:    "deployment-output",
			})
		}
		linkParts := []string{}
		if truth.TemplateLink != nil && strings.TrimSpace(*truth.TemplateLink) != "" {
			linkParts = append(linkParts, "template="+compactLinkLab(*truth.TemplateLink))
		}
		if truth.ParametersLink != nil && strings.TrimSpace(*truth.ParametersLink) != "" {
			linkParts = append(linkParts, "parameters="+compactLinkLab(*truth.ParametersLink))
		}
		if len(linkParts) > 0 {
			surfaces = append(surfaces, liveTokensCredentialSurfaceTruth{
				AccessPath:     "deployment-history",
				AssetID:        truth.ID,
				AssetKind:      "ArmDeployment",
				AssetName:      truth.Name,
				OperatorSignal: strings.Join(linkParts, "; "),
				Priority:       "low",
				SurfaceType:    "linked-deployment-content",
			})
		}
	}
	return surfaces
}

func tokenCredentialSurfacesFromLiveVMs(context liveVMSContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := []liveTokensCredentialSurfaceTruth{}
	for _, truth := range context.VMAssets {
		identityIDs := slices.Clone(truth.IdentityIDs)
		if len(identityIDs) == 0 {
			continue
		}
		operatorSignal := "public-ip=none; identities=" + strconv.Itoa(len(identityIDs))
		priority := "medium"
		if len(truth.PublicIPs) > 0 && strings.TrimSpace(truth.PublicIPs[0]) != "" {
			operatorSignal = "public-ip=" + truth.PublicIPs[0] + "; identities=" + strconv.Itoa(len(identityIDs))
			priority = "high"
		}
		surfaces = append(surfaces, liveTokensCredentialSurfaceTruth{
			AccessPath:     "imds",
			AssetID:        truth.ID,
			AssetKind:      strings.ToUpper(firstNonEmpty(truth.VMType, "vm")),
			AssetName:      truth.Name,
			OperatorSignal: operatorSignal,
			Priority:       priority,
			SurfaceType:    "managed-identity-token",
		})
	}
	return surfaces
}

func tokenCredentialSurfacesFromLiveVMSS(context liveVMSSContextArtifact) []liveTokensCredentialSurfaceTruth {
	surfaces := []liveTokensCredentialSurfaceTruth{}
	for _, truth := range context.VMSSAssets {
		identityIDs := slices.Clone(truth.IdentityIDs)
		if len(identityIDs) == 0 {
			continue
		}
		operatorSignal := "public-ip=none; identities=" + strconv.Itoa(len(identityIDs))
		if truth.PublicIPConfigurationCount > 0 {
			operatorSignal = "public-ip-configs=" + strconv.Itoa(truth.PublicIPConfigurationCount) + "; identities=" + strconv.Itoa(len(identityIDs))
		}
		surfaces = append(surfaces, liveTokensCredentialSurfaceTruth{
			AccessPath:     "imds",
			AssetID:        truth.ID,
			AssetKind:      "VMSS",
			AssetName:      truth.Name,
			OperatorSignal: operatorSignal,
			Priority:       "medium",
			SurfaceType:    "managed-identity-token",
		})
	}
	return surfaces
}

func valueOrUnknownLab(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func stringPtrValueLab(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func compactLinkLab(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	if parsed, err := url.Parse(text); err == nil && parsed.Host != "" && parsed.Path != "" {
		return parsed.Host + parsed.Path
	}
	return text
}

func keyVaultReferenceIdentitySummaryLab(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	if strings.EqualFold(text, "systemassigned") {
		return "SystemAssigned"
	}
	parts := strings.Split(strings.Trim(text, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return text
}
