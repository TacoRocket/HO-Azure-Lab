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

func captureLiveAzureContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	accountShowCmd := exec.Command("az", "account", "show", "--output", "json")
	accountShowOutput, err := runProgressCommand("az account show (live validation context)", workingDir, env, progressWriter, accountShowCmd)
	if err != nil {
		return fmt.Errorf("az account show failed: %s", strings.TrimSpace(string(accountShowOutput)))
	}
	account := azAccountShow{}
	if err := json.Unmarshal(accountShowOutput, &account); err != nil {
		return fmt.Errorf("parse az account show output: %w", err)
	}

	tokenCmd := exec.Command("az", "account", "get-access-token", "--resource-type", "arm", "--output", "json")
	tokenOutput, err := runProgressCommand("az account get-access-token (live validation context)", workingDir, env, progressWriter, tokenCmd)
	if err != nil {
		return fmt.Errorf("az account get-access-token failed: %s", strings.TrimSpace(string(tokenOutput)))
	}
	token := azAccessTokenResponse{}
	if err := json.Unmarshal(tokenOutput, &token); err != nil {
		return fmt.Errorf("parse az account get-access-token output: %w", err)
	}
	claims := decodeJWTPayload(token.AccessToken)
	principalID, principalName := currentPrincipalFromClaims(claims)

	artifact := liveAzureContextArtifact{
		TenantID:        firstNonEmpty(claims["tid"], account.TenantID),
		SubscriptionID:  firstNonEmpty(account.ID, claims["xms_mirid"]),
		PrincipalID:     principalID,
		PrincipalType:   principalTypeFromClaims(claims),
		PrincipalName:   firstNonEmpty(principalName, account.User.Name),
		AccountUserName: account.User.Name,
		AccountUserType: account.User.Type,
	}
	if artifact.SubscriptionID == claims["xms_mirid"] {
		artifact.SubscriptionID = account.ID
	}
	if err := WriteJSON(filepath.Join(outdir, "live-azure-context.json"), artifact); err != nil {
		return fmt.Errorf("write live Azure context artifact: %w", err)
	}
	return nil
}

func captureLiveManagedIdentitiesContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	identityCmd := exec.Command("az", "identity", "list", "--output", "json")
	identityOutput, err := runProgressCommand("az identity list (managed-identities validation context)", workingDir, env, progressWriter, identityCmd)
	if err != nil {
		return fmt.Errorf("az identity list failed: %s", strings.TrimSpace(string(identityOutput)))
	}
	identities := []azManagedIdentityShow{}
	if err := json.Unmarshal(identityOutput, &identities); err != nil {
		return fmt.Errorf("parse az identity list output: %w", err)
	}

	resourceCmd := exec.Command(
		"az", "resource", "list",
		"--query", "[?identity!=null].{id:id,name:name,type:type,identity:identity}",
		"--output", "json",
	)
	resourceOutput, err := runProgressCommand("az resource list (managed-identities validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azIdentityEnabledResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az resource list output: %w", err)
	}

	userAssignedAttachments := map[string][]string{}
	truths := []liveManagedIdentityTruth{}
	for _, resource := range resources {
		if !managedIdentitySupportedResourceType(resource.Type) {
			continue
		}
		identityType := strings.ToLower(strings.TrimSpace(resource.Identity.Type))
		if strings.Contains(identityType, "systemassigned") && strings.TrimSpace(resource.Identity.PrincipalID) != "" {
			truths = append(truths, liveManagedIdentityTruth{
				DisplayName:  resource.Name,
				PrincipalID:  resource.Identity.PrincipalID,
				IdentityType: "systemAssigned",
				AttachedTo:   []string{resource.ID},
			})
		}
		for identityID := range resource.Identity.UserAssignedIdentities {
			userAssignedAttachments[identityID] = append(userAssignedAttachments[identityID], resource.ID)
		}
	}
	for _, identity := range identities {
		attachments := userAssignedAttachments[identity.ID]
		if len(attachments) == 0 {
			continue
		}
		sort.Strings(attachments)
		truths = append(truths, liveManagedIdentityTruth{
			DisplayName:  identity.Name,
			PrincipalID:  identity.PrincipalID,
			IdentityType: "userAssigned",
			AttachedTo:   attachments,
		})
	}

	artifact := liveManagedIdentitiesContextArtifact{
		Identities: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-managed-identities-context.json"), artifact); err != nil {
		return fmt.Errorf("write live managed identities context artifact: %w", err)
	}
	return nil
}

func captureLiveWorkloadsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	resourceCmd := exec.Command(
		"az", "resource", "list",
		"--query", "[?type=='Microsoft.Compute/virtualMachines' || type=='Microsoft.Compute/virtualMachineScaleSets' || type=='Microsoft.Web/sites' || type=='Microsoft.App/containerApps' || type=='Microsoft.ContainerInstance/containerGroups'].{id:id,name:name,type:type,kind:kind,identity:identity}",
		"--output", "json",
	)
	resourceOutput, err := runProgressCommand("az resource list (workloads validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azWorkloadResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az resource list output: %w", err)
	}

	truths := []liveWorkloadTruth{}
	for _, resource := range resources {
		if !workloadSupportedResourceType(resource.Type) {
			continue
		}
		assetKind := workloadAssetKind(resource.Type, resource.Kind)
		if assetKind == "" {
			continue
		}
		truths = append(truths, liveWorkloadTruth{
			AssetID:      resource.ID,
			AssetKind:    assetKind,
			AssetName:    resource.Name,
			IdentityType: strings.TrimSpace(resource.Identity.Type),
			IdentityIDs:  workloadIdentityIDs(resource),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].AssetID < truths[j].AssetID
	})

	artifact := liveWorkloadsContextArtifact{
		Workloads: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-workloads-context.json"), artifact); err != nil {
		return fmt.Errorf("write live workloads context artifact: %w", err)
	}
	return nil
}

func captureLiveAppServicesContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	resourceCmd := exec.Command(
		"az", "webapp", "list",
		"--query", "[?contains(to_string(kind), 'functionapp') == `false`].{id:id,name:name,kind:kind,defaultHostName:defaultHostName,publicNetworkAccess:publicNetworkAccess,identity:identity}",
		"--output", "json",
	)
	resourceOutput, err := runProgressCommand("az webapp list (app-services validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az webapp list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azAppServiceResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az webapp list output: %w", err)
	}

	truths := []liveAppServiceTruth{}
	for _, resource := range resources {
		if strings.Contains(strings.ToLower(resource.Kind), "functionapp") {
			continue
		}
		truths = append(truths, liveAppServiceTruth{
			ID:                  resource.ID,
			Name:                resource.Name,
			Hostname:            strings.TrimSpace(resource.DefaultHostName),
			PublicNetworkAccess: strings.TrimSpace(resource.PublicNetworkAccess),
			IdentityType:        strings.TrimSpace(resource.Identity.Type),
			IdentityIDs:         appServiceIdentityIDs(resource),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveAppServicesContextArtifact{
		AppServices: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-app-services-context.json"), artifact); err != nil {
		return fmt.Errorf("write live app services context artifact: %w", err)
	}
	return nil
}

func captureLiveFunctionsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	resourceCmd := exec.Command(
		"az", "webapp", "list",
		"--query", "[?contains(to_string(kind), 'functionapp')].{id:id,name:name,kind:kind,defaultHostName:defaultHostName,publicNetworkAccess:publicNetworkAccess,identity:identity}",
		"--output", "json",
	)
	resourceOutput, err := runProgressCommand("az webapp list (functions validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az webapp list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azAppServiceResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az webapp list output: %w", err)
	}

	truths := []liveFunctionTruth{}
	for _, resource := range resources {
		if !strings.Contains(strings.ToLower(resource.Kind), "functionapp") {
			continue
		}
		truths = append(truths, liveFunctionTruth{
			ID:                  resource.ID,
			Name:                resource.Name,
			Hostname:            strings.TrimSpace(resource.DefaultHostName),
			PublicNetworkAccess: strings.TrimSpace(resource.PublicNetworkAccess),
			IdentityType:        strings.TrimSpace(resource.Identity.Type),
			IdentityIDs:         appServiceIdentityIDs(resource),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveFunctionsContextArtifact{
		FunctionApps: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-functions-context.json"), artifact); err != nil {
		return fmt.Errorf("write live functions context artifact: %w", err)
	}
	return nil
}

func captureLiveContainerAppsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	resourceCmd := exec.Command(
		"az", "containerapp", "list", "--output", "json",
	)
	resourceOutput, err := runProgressCommand("az containerapp list (container-apps validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az containerapp list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azContainerAppResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az containerapp list output: %w", err)
	}

	truths := []liveContainerAppTruth{}
	for _, resource := range resources {
		environmentID := strings.TrimSpace(resource.Properties.ManagedEnvironmentID)
		if environmentID == "" {
			environmentID = strings.TrimSpace(resource.Properties.EnvironmentID)
		}
		truths = append(truths, liveContainerAppTruth{
			ID:                  resource.ID,
			Name:                resource.Name,
			DefaultHostname:     strings.TrimSpace(resource.Properties.Configuration.Ingress.FQDN),
			EnvironmentID:       environmentID,
			ExternalIngress:     resource.Properties.Configuration.Ingress.External,
			IngressTargetPort:   resource.Properties.Configuration.Ingress.TargetPort,
			IngressTransport:    strings.TrimSpace(resource.Properties.Configuration.Ingress.Transport),
			LatestReadyRevision: strings.TrimSpace(resource.Properties.LatestReadyRevision),
			LatestRevision:      strings.TrimSpace(resource.Properties.LatestRevision),
			RevisionMode:        strings.TrimSpace(resource.Properties.Configuration.ActiveRevisionsMode),
			IdentityType:        strings.TrimSpace(resource.Identity.Type),
			IdentityIDs:         userAssignedIdentityIDs(resource.Identity.UserAssignedIdentities),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveContainerAppsContextArtifact{
		ContainerApps: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-container-apps-context.json"), artifact); err != nil {
		return fmt.Errorf("write live container apps context artifact: %w", err)
	}
	return nil
}

func captureLiveContainerInstancesContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	resourceCmd := exec.Command("az", "container", "list", "--output", "json")
	resourceOutput, err := runProgressCommand("az container list (container-instances validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az container list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azContainerInstanceResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az container list output: %w", err)
	}

	truths := []liveContainerInstanceTruth{}
	for _, resource := range resources {
		exposedPorts := []int{}
		for _, port := range resource.IPAddress.Ports {
			if port.Port == 0 {
				continue
			}
			exposedPorts = append(exposedPorts, port.Port)
		}
		sort.Ints(exposedPorts)
		exposedPorts = slices.Compact(exposedPorts)

		containerImages := []string{}
		for _, container := range resource.Containers {
			if strings.TrimSpace(container.Image) == "" {
				continue
			}
			containerImages = append(containerImages, strings.TrimSpace(container.Image))
		}
		sort.Strings(containerImages)
		containerImages = slices.Compact(containerImages)

		subnetIDs := []string{}
		for _, subnet := range resource.SubnetIDs {
			if strings.TrimSpace(subnet.ID) == "" {
				continue
			}
			subnetIDs = append(subnetIDs, subnet.ID)
		}
		sort.Strings(subnetIDs)
		subnetIDs = slices.Compact(subnetIDs)

		truths = append(truths, liveContainerInstanceTruth{
			ID:                resource.ID,
			Name:              resource.Name,
			PublicIPAddress:   strings.TrimSpace(resource.IPAddress.IP),
			FQDN:              strings.TrimSpace(resource.IPAddress.FQDN),
			ExposedPorts:      exposedPorts,
			RestartPolicy:     strings.TrimSpace(resource.RestartPolicy),
			OSType:            strings.TrimSpace(resource.OSType),
			ProvisioningState: strings.TrimSpace(resource.ProvisioningState),
			ContainerCount:    len(resource.Containers),
			ContainerImages:   containerImages,
			SubnetIDs:         subnetIDs,
			IdentityType:      strings.TrimSpace(resource.Identity.Type),
			IdentityIDs:       userAssignedIdentityIDs(resource.Identity.UserAssignedIdentities),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveContainerInstancesContextArtifact{
		ContainerInstances: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-container-instances-context.json"), artifact); err != nil {
		return fmt.Errorf("write live container instances context artifact: %w", err)
	}
	return nil
}
