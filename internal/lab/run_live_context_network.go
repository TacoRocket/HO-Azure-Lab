package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

func splitAzureCSVField(value string) []string {
	items := []string{}
	for _, part := range strings.Split(strings.TrimSpace(value), ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		items = append(items, trimmed)
	}
	sort.Strings(items)
	return slices.Compact(items)
}

func captureLiveEndpointsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	truths := []liveEndpointTruth{}

	vmCmd := exec.Command("az", "vm", "list", "-d", "--output", "json")
	vmOutput, err := runProgressCommand("az vm list -d (endpoints validation context)", workingDir, env, progressWriter, vmCmd)
	if err != nil {
		return fmt.Errorf("az vm list -d failed: %s", strings.TrimSpace(string(vmOutput)))
	}
	vms := []azVMDetailedResource{}
	if err := json.Unmarshal(vmOutput, &vms); err != nil {
		return fmt.Errorf("parse az vm list -d output: %w", err)
	}
	for _, vm := range vms {
		for _, publicIP := range splitAzureCSVField(vm.PublicIPs) {
			truths = append(truths, liveEndpointTruth{
				Endpoint:        publicIP,
				EndpointType:    "ip",
				ExposureFamily:  "public-ip",
				IngressPath:     "direct-vm-ip",
				SourceAssetID:   strings.TrimSpace(vm.ID),
				SourceAssetKind: "VM",
				SourceAssetName: strings.TrimSpace(vm.Name),
			})
		}
	}

	webCmd := exec.Command(
		"az", "resource", "list", "--resource-type", "Microsoft.Web/sites",
		"--query", "[].{id:id,name:name,kind:kind,defaultHostName:defaultHostName}",
		"--output", "json",
	)
	webOutput, err := runProgressCommand("az resource list (endpoints web validation context)", workingDir, env, progressWriter, webCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for Microsoft.Web/sites: %s", strings.TrimSpace(string(webOutput)))
	}
	webResources := []azAppServiceResource{}
	if err := json.Unmarshal(webOutput, &webResources); err != nil {
		return fmt.Errorf("parse web workload list output: %w", err)
	}
	for _, listed := range webResources {
		resource := listed
		if strings.TrimSpace(resource.DefaultHostName) == "" && strings.TrimSpace(resource.ID) != "" {
			showCmd := exec.Command(
				"az", "resource", "show",
				"--ids", strings.TrimSpace(resource.ID),
				"--api-version", "2024-04-01",
				"--output", "json",
			)
			showOutput, err := runProgressCommand("az resource show (endpoints web validation context)", workingDir, env, progressWriter, showCmd)
			if err != nil {
				return fmt.Errorf("az resource show failed for %s: %s", resource.ID, strings.TrimSpace(string(showOutput)))
			}
			if err := json.Unmarshal(showOutput, &resource); err != nil {
				return fmt.Errorf("parse web workload show output for %s: %w", listed.ID, err)
			}
		}

		hostname := strings.TrimSpace(firstNonEmptyString(resource.DefaultHostName, resource.Properties.DefaultHostName))
		if hostname == "" {
			continue
		}
		assetKind := workloadAssetKind("Microsoft.Web/sites", resource.Kind)
		ingressPath := "azurewebsites-default-hostname"
		if assetKind == "FunctionApp" {
			ingressPath = "azure-functions-default-hostname"
		}
		truths = append(truths, liveEndpointTruth{
			Endpoint:        hostname,
			EndpointType:    "hostname",
			ExposureFamily:  "managed-web-hostname",
			IngressPath:     ingressPath,
			SourceAssetID:   strings.TrimSpace(resource.ID),
			SourceAssetKind: assetKind,
			SourceAssetName: strings.TrimSpace(resource.Name),
		})
	}

	containerAppsCmd := exec.Command("az", "containerapp", "list", "--output", "json")
	containerAppsOutput, err := runProgressCommand("az containerapp list (endpoints validation context)", workingDir, env, progressWriter, containerAppsCmd)
	if err != nil {
		return fmt.Errorf("az containerapp list failed: %s", strings.TrimSpace(string(containerAppsOutput)))
	}
	containerApps := []azContainerAppResource{}
	if err := json.Unmarshal(containerAppsOutput, &containerApps); err != nil {
		return fmt.Errorf("parse az containerapp list output: %w", err)
	}
	for _, resource := range containerApps {
		if resource.Properties.Configuration.Ingress.External == nil || !*resource.Properties.Configuration.Ingress.External {
			continue
		}
		hostname := strings.TrimSpace(resource.Properties.Configuration.Ingress.FQDN)
		if hostname == "" {
			continue
		}
		truths = append(truths, liveEndpointTruth{
			Endpoint:        hostname,
			EndpointType:    "hostname",
			ExposureFamily:  "managed-web-hostname",
			IngressPath:     "azure-container-apps-default-hostname",
			SourceAssetID:   strings.TrimSpace(resource.ID),
			SourceAssetKind: "ContainerApp",
			SourceAssetName: strings.TrimSpace(resource.Name),
		})
	}

	containerInstancesCmd := exec.Command("az", "container", "list", "--output", "json")
	containerInstancesOutput, err := runProgressCommand("az container list (endpoints validation context)", workingDir, env, progressWriter, containerInstancesCmd)
	if err != nil {
		return fmt.Errorf("az container list failed: %s", strings.TrimSpace(string(containerInstancesOutput)))
	}
	containerInstances := []azContainerInstanceResource{}
	if err := json.Unmarshal(containerInstancesOutput, &containerInstances); err != nil {
		return fmt.Errorf("parse az container list output: %w", err)
	}
	for _, resource := range containerInstances {
		if publicIP := strings.TrimSpace(resource.IPAddress.IP); publicIP != "" {
			truths = append(truths, liveEndpointTruth{
				Endpoint:        publicIP,
				EndpointType:    "ip",
				ExposureFamily:  "public-ip",
				IngressPath:     "azure-container-instances-public-ip",
				SourceAssetID:   strings.TrimSpace(resource.ID),
				SourceAssetKind: "ContainerInstance",
				SourceAssetName: strings.TrimSpace(resource.Name),
			})
		}
		if hostname := strings.TrimSpace(resource.IPAddress.FQDN); hostname != "" {
			truths = append(truths, liveEndpointTruth{
				Endpoint:        hostname,
				EndpointType:    "hostname",
				ExposureFamily:  "managed-container-fqdn",
				IngressPath:     "azure-container-instances-fqdn",
				SourceAssetID:   strings.TrimSpace(resource.ID),
				SourceAssetKind: "ContainerInstance",
				SourceAssetName: strings.TrimSpace(resource.Name),
			})
		}
	}

	sort.SliceStable(truths, func(i, j int) bool {
		if truths[i].Endpoint != truths[j].Endpoint {
			return truths[i].Endpoint < truths[j].Endpoint
		}
		if truths[i].SourceAssetName != truths[j].SourceAssetName {
			return truths[i].SourceAssetName < truths[j].SourceAssetName
		}
		return truths[i].IngressPath < truths[j].IngressPath
	})

	artifact := liveEndpointsContextArtifact{Endpoints: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-endpoints-context.json"), artifact); err != nil {
		return fmt.Errorf("write live endpoints context artifact: %w", err)
	}
	return nil
}

func networkEffectiveProtocol(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "*" {
		return "Any"
	}
	return strings.ToUpper(trimmed)
}

func networkEffectiveIsPrivatePrefix(value string) bool {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return prefix.Addr().IsPrivate()
}

func networkEffectiveScopeLabel(scopeType, scopeID, ruleName string) string {
	label := "subnet-nsg"
	if scopeType == "nic" {
		label = "nic-nsg"
	}
	scopeName := firstNonEmptyString(resourceNameFromAzureID(scopeID), scopeID, "unknown")
	scopeRef := scopeName
	if resourceGroup := resourceGroupFromAzureID(scopeID); resourceGroup != "" {
		scopeRef = resourceGroup + "/" + scopeName
	}
	return label + ":" + scopeRef + "/" + firstNonEmptyString(strings.TrimSpace(ruleName), "allow-rule")
}

func networkEffectiveConfidence(sources []string) string {
	lowered := []string{}
	for _, source := range sources {
		value := strings.ToLower(strings.TrimSpace(source))
		if value != "" {
			lowered = append(lowered, value)
		}
	}
	for _, value := range lowered {
		if value == "any" || value == "internet" || value == "0.0.0.0/0" || value == "::/0" {
			return "high"
		}
	}
	for _, value := range lowered {
		if value == "azureloadbalancer" {
			return "medium"
		}
	}
	for _, source := range sources {
		value := strings.TrimSpace(source)
		if strings.Contains(value, "/") && !networkEffectiveIsPrivatePrefix(value) {
			return "medium"
		}
	}
	for _, value := range lowered {
		if value == "virtualnetwork" {
			return "low"
		}
	}
	for _, source := range sources {
		if networkEffectiveIsPrivatePrefix(source) {
			return "low"
		}
	}
	return "medium"
}

func networkEffectiveTruthFromEvidence(assetID, assetName, endpoint string, relatedIDs []string, evidence []liveNetworkPortEvidence) liveNetworkEffectiveTruth {
	highest := "low"
	if len(evidence) > 0 {
		rank := map[string]int{"high": 0, "medium": 1, "low": 2}
		sort.SliceStable(evidence, func(i, j int) bool {
			return rank[strings.ToLower(evidence[i].ExposureConfidence)] < rank[strings.ToLower(evidence[j].ExposureConfidence)]
		})
		highest = strings.ToLower(strings.TrimSpace(evidence[0].ExposureConfidence))
	}

	internetPorts := []string{}
	constrainedPorts := []string{}
	observedPaths := []string{}
	joinedRelatedIDs := append([]string{assetID}, relatedIDs...)
	explicitAllowCount := 0

	for _, row := range evidence {
		observedPaths = append(observedPaths, row.AllowSourceSummary)
		joinedRelatedIDs = append(joinedRelatedIDs, row.RelatedIDs...)
		if row.AllowSourceSummary == "no Azure NSG visible on NIC or subnet" {
			continue
		}
		explicitAllowCount++
		portLabel := strings.ToUpper(strings.TrimSpace(row.Protocol)) + "/" + strings.TrimSpace(row.Port)
		sourceFragment := strings.Split(row.AllowSourceSummary, " via ")[0]
		lowered := strings.ToLower(sourceFragment)
		if strings.Contains(lowered, "any") || strings.Contains(lowered, "internet") || strings.Contains(lowered, "0.0.0.0/0") || strings.Contains(lowered, "::/0") {
			internetPorts = append(internetPorts, portLabel)
			continue
		}
		constrainedPorts = append(constrainedPorts, portLabel)
	}

	summaryBoundary := "low-confidence triage clue rather than proof of exposure"
	if explicitAllowCount > 0 {
		summaryBoundary = "not proof of full effective reachability"
	}

	return liveNetworkEffectiveTruth{
		AssetID:              strings.TrimSpace(assetID),
		AssetName:            strings.TrimSpace(assetName),
		Endpoint:             strings.TrimSpace(endpoint),
		EndpointType:         "ip",
		EffectiveExposure:    highest,
		InternetExposedPorts: compactSortedStrings(internetPorts),
		ConstrainedPorts:     compactSortedStrings(constrainedPorts),
		ObservedPaths:        compactSortedStrings(observedPaths),
		RelatedIDs:           compactSortedStrings(joinedRelatedIDs),
		SummaryBoundary:      summaryBoundary,
	}
}

func networkPortTruthRowsFromEvidence(assetID, assetName, endpoint string, evidence []liveNetworkPortEvidence) []liveNetworkPortTruth {
	rows := []liveNetworkPortTruth{}
	for _, row := range evidence {
		rows = append(rows, liveNetworkPortTruth{
			AssetID:            strings.TrimSpace(assetID),
			AssetName:          strings.TrimSpace(assetName),
			Endpoint:           strings.TrimSpace(endpoint),
			Protocol:           strings.TrimSpace(row.Protocol),
			Port:               strings.TrimSpace(row.Port),
			AllowSourceSummary: strings.TrimSpace(row.AllowSourceSummary),
			ExposureConfidence: strings.TrimSpace(row.ExposureConfidence),
			RelatedIDs:         compactSortedStrings(append([]string{assetID}, row.RelatedIDs...)),
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		rank := map[string]int{"high": 0, "medium": 1, "low": 2}
		if rank[strings.ToLower(rows[i].ExposureConfidence)] != rank[strings.ToLower(rows[j].ExposureConfidence)] {
			return rank[strings.ToLower(rows[i].ExposureConfidence)] < rank[strings.ToLower(rows[j].ExposureConfidence)]
		}
		if rows[i].AssetName != rows[j].AssetName {
			return rows[i].AssetName < rows[j].AssetName
		}
		if rows[i].Endpoint != rows[j].Endpoint {
			return rows[i].Endpoint < rows[j].Endpoint
		}
		if rows[i].Port != rows[j].Port {
			return rows[i].Port < rows[j].Port
		}
		return rows[i].AllowSourceSummary < rows[j].AllowSourceSummary
	})
	return rows
}

func collectVMLiveNetworkEvidence(workingDir string, env []string, progressWriter io.Writer) ([]liveVMNetworkEvidence, error) {
	vmListCmd := exec.Command("az", "vm", "list", "-d", "--output", "json")
	vmListOutput, err := runProgressCommand("az vm list -d (network validation context)", workingDir, env, progressWriter, vmListCmd)
	if err != nil {
		return nil, fmt.Errorf("az vm list -d failed: %s", strings.TrimSpace(string(vmListOutput)))
	}
	vms := []azVMDetailedResource{}
	if err := json.Unmarshal(vmListOutput, &vms); err != nil {
		return nil, fmt.Errorf("parse az vm list -d output: %w", err)
	}

	truths := []liveVMNetworkEvidence{}
	for _, listed := range vms {
		publicIPs := splitAzureCSVField(listed.PublicIPs)
		if len(publicIPs) == 0 {
			continue
		}
		vmShowCmd := exec.Command("az", "vm", "show", "--ids", strings.TrimSpace(listed.ID), "--output", "json")
		vmShowOutput, err := runProgressCommand("az vm show (network validation context)", workingDir, env, progressWriter, vmShowCmd)
		if err != nil {
			return nil, fmt.Errorf("az vm show failed for %s: %s", listed.ID, strings.TrimSpace(string(vmShowOutput)))
		}
		vm := azVMShowResource{}
		if err := json.Unmarshal(vmShowOutput, &vm); err != nil {
			return nil, fmt.Errorf("parse az vm show output for %s: %w", listed.ID, err)
		}
		vmIdentityIDs := userAssignedIdentityIDs(vm.Identity.UserAssignedIdentities)
		vmBaseRelatedIDs := compactSortedStrings(append([]string{vm.ID}, vmIdentityIDs...))
		evidence := []liveNetworkPortEvidence{}
		nicRefs := vm.NetworkProfile.NetworkInterfaces
		if len(nicRefs) == 0 {
			nicRefs = vm.Properties.NetworkProfile.NetworkInterfaces
		}
		for _, nicRef := range nicRefs {
			nicShowCmd := exec.Command("az", "network", "nic", "show", "--ids", strings.TrimSpace(nicRef.ID), "--output", "json")
			nicShowOutput, err := runProgressCommand("az network nic show (network validation context)", workingDir, env, progressWriter, nicShowCmd)
			if err != nil {
				return nil, fmt.Errorf("az network nic show failed for %s: %s", nicRef.ID, strings.TrimSpace(string(nicShowOutput)))
			}
			nic := azNICResource{}
			if err := json.Unmarshal(nicShowOutput, &nic); err != nil {
				return nil, fmt.Errorf("parse az network nic show output for %s: %w", nicRef.ID, err)
			}
			nicBaseRelatedIDs := compactSortedStrings(append([]string{vm.ID, nic.ID}, vmIdentityIDs...))
			visibleRule := false
			appendRules := func(scopeType, scopeID string, rules []azNSGRule, baseRelatedIDs []string) {
				for _, rule := range rules {
					access := firstNonEmptyString(rule.Access, rule.Properties.Access)
					direction := firstNonEmptyString(rule.Direction, rule.Properties.Direction)
					if strings.ToLower(strings.TrimSpace(access)) != "allow" || strings.ToLower(strings.TrimSpace(direction)) != "inbound" {
						continue
					}
					visibleRule = true
					sources := compactSortedStrings(append(append([]string{}, rule.SourceAddressPrefixes...), rule.Properties.SourceAddressPrefixes...))
					sources = compactSortedStrings(append(sources, firstNonEmptyString(rule.SourceAddressPrefix, rule.Properties.SourceAddressPrefix)))
					if len(sources) == 0 {
						sources = []string{"Any"}
					}
					ports := compactSortedStrings(append(append([]string{}, rule.DestinationPortRanges...), rule.Properties.DestinationPortRanges...))
					ports = compactSortedStrings(append(ports, firstNonEmptyString(rule.DestinationPortRange, rule.Properties.DestinationPortRange)))
					if len(ports) == 0 {
						ports = []string{"any"}
					}
					for _, port := range ports {
						evidence = append(evidence, liveNetworkPortEvidence{
							AllowSourceSummary: strings.Join(sources, ", ") + " via " + networkEffectiveScopeLabel(scopeType, scopeID, rule.Name),
							ExposureConfidence: networkEffectiveConfidence(sources),
							Port:               strings.ReplaceAll(port, "*", "any"),
							Protocol:           networkEffectiveProtocol(firstNonEmptyString(rule.Protocol, rule.Properties.Protocol)),
							RelatedIDs:         compactSortedStrings(append(baseRelatedIDs, scopeID)),
						})
					}
				}
			}
			nicNSG := nic.NetworkSecurityGroup
			if nicNSG == nil {
				nicNSG = nic.Properties.NetworkSecurityGroup
			}
			if nicNSG != nil && strings.TrimSpace(nicNSG.ID) != "" {
				nsgCmd := exec.Command("az", "network", "nsg", "show", "--ids", strings.TrimSpace(nicNSG.ID), "--output", "json")
				nsgOutput, err := runProgressCommand("az network nsg show (network validation context)", workingDir, env, progressWriter, nsgCmd)
				if err != nil {
					if !azureAuthorizationFailure(nsgOutput) {
						return nil, fmt.Errorf("az network nsg show failed for %s: %s", nicNSG.ID, strings.TrimSpace(string(nsgOutput)))
					}
				} else {
					nsg := azNSGResource{}
					if err := json.Unmarshal(nsgOutput, &nsg); err != nil {
						return nil, fmt.Errorf("parse az network nsg show output for %s: %w", nicNSG.ID, err)
					}
					rules := nsg.SecurityRules
					if len(rules) == 0 {
						rules = nsg.Properties.SecurityRules
					}
					appendRules("nic", nsg.ID, rules, nicBaseRelatedIDs)
				}
			}
			ipConfigs := nic.IPConfigurations
			if len(ipConfigs) == 0 {
				ipConfigs = nic.Properties.IPConfigurations
			}
			for _, ipConfig := range ipConfigs {
				subnetRef := ipConfig.Subnet
				if subnetRef == nil {
					subnetRef = ipConfig.Properties.Subnet
				}
				if subnetRef == nil || strings.TrimSpace(subnetRef.ID) == "" {
					continue
				}
				subnetCmd := exec.Command("az", "network", "vnet", "subnet", "show", "--ids", strings.TrimSpace(subnetRef.ID), "--output", "json")
				subnetOutput, err := runProgressCommand("az network vnet subnet show (network validation context)", workingDir, env, progressWriter, subnetCmd)
				if err != nil {
					if azureAuthorizationFailure(subnetOutput) {
						continue
					}
					return nil, fmt.Errorf("az network vnet subnet show failed for %s: %s", subnetRef.ID, strings.TrimSpace(string(subnetOutput)))
				}
				subnet := azSubnetResource{}
				if err := json.Unmarshal(subnetOutput, &subnet); err != nil {
					return nil, fmt.Errorf("parse az network vnet subnet show output for %s: %w", subnetRef.ID, err)
				}
				subnetNSG := subnet.NetworkSecurityGroup
				if subnetNSG == nil {
					subnetNSG = subnet.Properties.NetworkSecurityGroup
				}
				if subnetNSG == nil || strings.TrimSpace(subnetNSG.ID) == "" {
					continue
				}
				nsgCmd := exec.Command("az", "network", "nsg", "show", "--ids", strings.TrimSpace(subnetNSG.ID), "--output", "json")
				nsgOutput, err := runProgressCommand("az network nsg show (network validation context)", workingDir, env, progressWriter, nsgCmd)
				if err != nil {
					if azureAuthorizationFailure(nsgOutput) {
						continue
					}
					return nil, fmt.Errorf("az network nsg show failed for %s: %s", subnetNSG.ID, strings.TrimSpace(string(nsgOutput)))
				}
				nsg := azNSGResource{}
				if err := json.Unmarshal(nsgOutput, &nsg); err != nil {
					return nil, fmt.Errorf("parse az network nsg show output for %s: %w", subnetNSG.ID, err)
				}
				rules := nsg.SecurityRules
				if len(rules) == 0 {
					rules = nsg.Properties.SecurityRules
				}
				appendRules("subnet", nsg.ID, rules, nicBaseRelatedIDs)
			}
			if !visibleRule {
				evidence = append(evidence, liveNetworkPortEvidence{
					AllowSourceSummary: "no Azure NSG visible on NIC or subnet",
					ExposureConfidence: "low",
					Port:               "any",
					Protocol:           "any",
					RelatedIDs:         nicBaseRelatedIDs,
				})
			}
		}
		for _, publicIP := range publicIPs {
			truths = append(truths, liveVMNetworkEvidence{
				AssetID:    vm.ID,
				AssetName:  firstNonEmptyString(vm.Name, listed.Name),
				Endpoint:   publicIP,
				RelatedIDs: vmBaseRelatedIDs,
				Evidence:   evidence,
			})
		}
	}
	return truths, nil
}

func captureLiveNetworkEffectiveContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	truths := []liveNetworkEffectiveTruth{}
	vmTruths, err := collectVMLiveNetworkEvidence(workingDir, env, progressWriter)
	if err != nil {
		return err
	}
	for _, truth := range vmTruths {
		truths = append(truths, networkEffectiveTruthFromEvidence(truth.AssetID, truth.AssetName, truth.Endpoint, truth.RelatedIDs, truth.Evidence))
	}

	containerCmd := exec.Command("az", "container", "list", "--output", "json")
	containerOutput, err := runProgressCommand("az container list (network-effective validation context)", workingDir, env, progressWriter, containerCmd)
	if err != nil {
		return fmt.Errorf("az container list failed: %s", strings.TrimSpace(string(containerOutput)))
	}
	containerInstances := []azContainerInstanceResource{}
	if err := json.Unmarshal(containerOutput, &containerInstances); err != nil {
		return fmt.Errorf("parse az container list output: %w", err)
	}
	for _, resource := range containerInstances {
		if strings.TrimSpace(resource.IPAddress.IP) == "" {
			continue
		}
		relatedIDs := append([]string{strings.TrimSpace(resource.ID)}, userAssignedIdentityIDs(resource.Identity.UserAssignedIdentities)...)
		for _, subnet := range resource.SubnetIDs {
			relatedIDs = append(relatedIDs, strings.TrimSpace(subnet.ID))
		}
		truths = append(truths, networkEffectiveTruthFromEvidence(resource.ID, resource.Name, resource.IPAddress.IP, compactSortedStrings(relatedIDs), nil))
	}

	sort.SliceStable(truths, func(i, j int) bool {
		rank := map[string]int{"high": 0, "medium": 1, "low": 2}
		if rank[strings.ToLower(truths[i].EffectiveExposure)] != rank[strings.ToLower(truths[j].EffectiveExposure)] {
			return rank[strings.ToLower(truths[i].EffectiveExposure)] < rank[strings.ToLower(truths[j].EffectiveExposure)]
		}
		if truths[i].AssetName != truths[j].AssetName {
			return truths[i].AssetName < truths[j].AssetName
		}
		return truths[i].Endpoint < truths[j].Endpoint
	})

	artifact := liveNetworkEffectiveContextArtifact{EffectiveExposures: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-network-effective-context.json"), artifact); err != nil {
		return fmt.Errorf("write live network-effective context artifact: %w", err)
	}
	return nil
}

func captureLiveNetworkPortsContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	vmTruths, err := collectVMLiveNetworkEvidence(workingDir, env, progressWriter)
	if err != nil {
		return err
	}

	rows := []liveNetworkPortTruth{}
	for _, truth := range vmTruths {
		rows = append(rows, networkPortTruthRowsFromEvidence(truth.AssetID, truth.AssetName, truth.Endpoint, truth.Evidence)...)
	}

	artifact := liveNetworkPortsContextArtifact{NetworkPorts: rows}
	if err := WriteJSON(filepath.Join(outdir, "live-network-ports-context.json"), artifact); err != nil {
		return fmt.Errorf("write live network-ports context artifact: %w", err)
	}
	return nil
}

func dnsZoneReferenceKey(resourceID string) string {
	return strings.ToLower(strings.TrimSpace(resourceID))
}

func compactSortedStrings(values []string) []string {
	items := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		items = append(items, trimmed)
	}
	sort.Strings(items)
	return slices.Compact(items)
}

func collectPrivateDNSZoneReferences(
	workingDir string,
	env []string,
	progressWriter io.Writer,
) (map[string][]string, error) {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Network/privateEndpoints", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (dns private-endpoint validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return nil, fmt.Errorf("az resource list failed for private endpoints: %s", strings.TrimSpace(string(listOutput)))
	}
	privateEndpoints := []azPrivateEndpointResource{}
	if err := json.Unmarshal(listOutput, &privateEndpoints); err != nil {
		return nil, fmt.Errorf("parse private endpoint list output: %w", err)
	}

	references := map[string][]string{}
	for _, privateEndpoint := range privateEndpoints {
		endpointID := strings.TrimSpace(privateEndpoint.ID)
		endpointName := strings.TrimSpace(privateEndpoint.Name)
		resourceGroup := strings.TrimSpace(privateEndpoint.ResourceGroup)
		if endpointID == "" || endpointName == "" || resourceGroup == "" {
			resourceGroup = resourceGroupFromAzureID(endpointID)
		}
		if endpointID == "" || endpointName == "" || resourceGroup == "" {
			continue
		}

		groupCmd := exec.Command(
			"az", "network", "private-endpoint", "dns-zone-group", "list",
			"--endpoint-name", endpointName,
			"--resource-group", resourceGroup,
			"--output", "json",
		)
		groupOutput, err := runProgressCommand("az network private-endpoint dns-zone-group list (dns validation context)", workingDir, env, progressWriter, groupCmd)
		if err != nil {
			return nil, fmt.Errorf("az network private-endpoint dns-zone-group list failed for %s: %s", endpointID, strings.TrimSpace(string(groupOutput)))
		}
		zoneGroups := []azPrivateEndpointDNSZoneGroup{}
		if err := json.Unmarshal(groupOutput, &zoneGroups); err != nil {
			return nil, fmt.Errorf("parse private endpoint zone-group output for %s: %w", endpointID, err)
		}

		for _, zoneGroup := range zoneGroups {
			for _, zoneConfig := range privateEndpointDNSZoneConfigs(zoneGroup) {
				zoneID := strings.TrimSpace(zoneConfig.PrivateDNSZoneID)
				if zoneID == "" {
					zoneID = strings.TrimSpace(zoneConfig.Properties.PrivateDNSZoneID)
				}
				zoneKey := dnsZoneReferenceKey(zoneID)
				if zoneKey == "" {
					continue
				}
				references[zoneKey] = append(references[zoneKey], endpointID)
			}
		}
	}

	for zoneKey, endpointIDs := range references {
		references[zoneKey] = compactSortedStrings(endpointIDs)
	}
	return references, nil
}

func privateEndpointDNSZoneConfigs(group azPrivateEndpointDNSZoneGroup) []azPrivateEndpointDNSZoneConfig {
	if len(group.PrivateDNSZoneConfigs) > 0 {
		return group.PrivateDNSZoneConfigs
	}
	return group.Properties.PrivateDNSZoneConfigs
}

func captureLiveDNSContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	type zoneListSpec struct {
		resourceType string
		apiVersion   string
		zoneKind     string
	}

	listSpecs := []zoneListSpec{
		{resourceType: "Microsoft.Network/dnszones", apiVersion: "2018-05-01", zoneKind: "public"},
		{resourceType: "Microsoft.Network/privateDnsZones", apiVersion: "2020-06-01", zoneKind: "private"},
	}

	privateZoneReferences, err := collectPrivateDNSZoneReferences(workingDir, env, progressWriter)
	if err != nil {
		return err
	}

	truths := []liveDNSTruth{}
	for _, spec := range listSpecs {
		listCmd := exec.Command("az", "resource", "list", "--resource-type", spec.resourceType, "--output", "json")
		listOutput, err := runProgressCommand("az resource list (dns validation context)", workingDir, env, progressWriter, listCmd)
		if err != nil {
			return fmt.Errorf("az resource list failed for %s: %s", spec.resourceType, strings.TrimSpace(string(listOutput)))
		}
		listedZones := []azDNSZoneResource{}
		if err := json.Unmarshal(listOutput, &listedZones); err != nil {
			return fmt.Errorf("parse %s list output: %w", spec.resourceType, err)
		}

		for _, listedZone := range listedZones {
			zoneID := strings.TrimSpace(listedZone.ID)
			if zoneID == "" {
				continue
			}

			showCmd := exec.Command("az", "resource", "show", "--ids", zoneID, "--api-version", spec.apiVersion, "--output", "json")
			showOutput, err := runProgressCommand("az resource show (dns validation context)", workingDir, env, progressWriter, showCmd)
			if err != nil {
				return fmt.Errorf("az resource show failed for %s: %s", zoneID, strings.TrimSpace(string(showOutput)))
			}
			zone := azDNSZoneResource{}
			if err := json.Unmarshal(showOutput, &zone); err != nil {
				return fmt.Errorf("parse az resource show output for %s: %w", zoneID, err)
			}

			nameServers := compactSortedStrings(zone.Properties.NameServers)
			relatedIDs := []string{zoneID}
			privateEndpointReferenceCount := (*int)(nil)
			if spec.zoneKind == "private" {
				privateEndpointIDs := privateZoneReferences[dnsZoneReferenceKey(zoneID)]
				if privateEndpointIDs == nil {
					privateEndpointIDs = []string{}
				}
				count := len(privateEndpointIDs)
				privateEndpointReferenceCount = &count
				relatedIDs = append(relatedIDs, privateEndpointIDs...)
			}

			truths = append(truths, liveDNSTruth{
				ID:                              zoneID,
				Name:                            strings.TrimSpace(zone.Name),
				ResourceGroup:                   firstNonEmptyString(strings.TrimSpace(zone.ResourceGroup), resourceGroupFromAzureID(zoneID)),
				Location:                        strings.TrimSpace(zone.Location),
				ZoneKind:                        spec.zoneKind,
				RecordSetCount:                  zone.Properties.NumberOfRecordSets,
				MaxRecordSetCount:               zone.Properties.MaxNumberOfRecordSets,
				NameServers:                     nameServers,
				LinkedVirtualNetworkCount:       zone.Properties.NumberOfVirtualNetworkLinks,
				RegistrationVirtualNetworkCount: zone.Properties.NumberOfVirtualNetworkLinksRegistration,
				PrivateEndpointReferenceCount:   privateEndpointReferenceCount,
				RelatedIDs:                      compactSortedStrings(relatedIDs),
			})
		}
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveDNSContextArtifact{DNSZones: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-dns-context.json"), artifact); err != nil {
		return fmt.Errorf("write live dns context artifact: %w", err)
	}
	return nil
}
