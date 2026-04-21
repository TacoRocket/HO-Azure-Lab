package lab

import (
	"fmt"
	"strings"
)

func findVMRowByID(payload map[string]any, vmID string) map[string]any {
	rows, _ := payload["vm_assets"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(vmID) {
			return rowMap
		}
	}
	return nil
}

func findVMFindingByID(payload map[string]any, findingID string) map[string]any {
	rows, _ := payload["findings"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if rowID == findingID {
			return rowMap
		}
	}
	return nil
}

func findVMSSRowByID(payload map[string]any, vmssID string) map[string]any {
	rows, _ := payload["vmss_assets"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(vmssID) {
			return rowMap
		}
	}
	return nil
}

func findNICRowByID(payload map[string]any, nicID string) map[string]any {
	rows, _ := payload["nic_assets"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(nicID) {
			return rowMap
		}
	}
	return nil
}

func validateNICsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveNICContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "nics" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-nics-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live nics context artifact",
			"lab runner nics context capture",
			"nics validation should compare the tool payload against recorded Azure NIC truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["nic_assets"].([]any)
	if len(rows) != len(context.NICAssets) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d nic rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.NICAssets)),
			"nics row selection or Azure-backed validation context",
			"nics should keep visible NIC rows aligned with the Azure NICs the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.NICAssets {
		row := findNICRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-nic-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible NIC row for id %q", label, truth.ID),
				"nics asset visibility or Azure-backed validation context",
				"nics should keep visible Azure NIC assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkOptionalString := func(field string, expected string, likelySeam string, expectedOutcome string) {
			observed, _ := row[field].(string)
			if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced NIC id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkResourceIDList := func(field string, expected []string, likelySeam string, expectedOutcome string) {
			observedValues := rowStringList(row, field)
			observedSet := normalizeStringSet(observedValues)
			for _, expectedValue := range expected {
				if _, ok := observedSet[normalizeResourceID(expectedValue)]; ok {
					continue
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s surfaced NIC id %q with %s %v, but Azure reports %v", label, truth.ID, field, observedValues, expected),
					likelySeam,
					expectedOutcome,
				))
				return
			}
			if len(expected) != len(observedSet) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s surfaced NIC id %q with %s %v, but Azure reports %v", label, truth.ID, field, observedValues, expected),
					likelySeam,
					expectedOutcome,
				))
			}
		}
		checkIPList := func(field string, expected []string, likelySeam string, expectedOutcome string) {
			expectedSet := normalizePlainStringSet(expected)
			observedValues := rowStringList(row, field)
			observedSet := normalizePlainStringSet(observedValues)
			if len(expectedSet) == len(observedSet) {
				matches := true
				for expectedValue := range expectedSet {
					if _, ok := observedSet[expectedValue]; !ok {
						matches = false
						break
					}
				}
				if matches {
					return
				}
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced NIC id %q with %s %v, but Azure reports %v", label, truth.ID, field, observedValues, expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkOptionalString("name", truth.Name, "nics naming or Azure-backed validation context", "nics should keep the NIC name aligned with the Azure asset it is summarizing")
		checkOptionalString("attached_asset_id", truth.AttachedAssetID, "nics attachment rendering or Azure-backed validation context", "nics should keep attached asset IDs aligned with the Azure NIC it is summarizing")
		checkOptionalString("attached_asset_name", truth.AttachedAssetName, "nics attachment rendering or Azure-backed validation context", "nics should keep attached asset names aligned with the Azure NIC it is summarizing")
		checkOptionalString("network_security_group_id", truth.NetworkSecurityGroupID, "nics NSG rendering or Azure-backed validation context", "nics should keep NIC-level NSG context aligned with the Azure NIC it is summarizing")
		checkIPList("private_ips", truth.PrivateIPs, "nics private IP rendering or Azure-backed validation context", "nics should keep private IPs aligned with the Azure NIC it is summarizing")
		checkResourceIDList("public_ip_ids", truth.PublicIPIDs, "nics public IP rendering or Azure-backed validation context", "nics should keep public IP references aligned with the Azure NIC it is summarizing")
		checkResourceIDList("subnet_ids", truth.SubnetIDs, "nics subnet rendering or Azure-backed validation context", "nics should keep subnet references aligned with the Azure NIC it is summarizing")
		checkResourceIDList("vnet_ids", truth.VnetIDs, "nics vnet rendering or Azure-backed validation context", "nics should keep VNet references aligned with the Azure NIC it is summarizing")
	}

	return findings
}

func validateVMSPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveVMSContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "vms" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-vms-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live vms context artifact",
			"lab runner vms context capture",
			"vms validation should compare the tool payload against recorded Azure VM truth instead of favorite rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["vm_assets"].([]any)
	if len(rows) != len(context.VMAssets) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d vm rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.VMAssets)),
			"vms row selection or Azure-backed validation context",
			"vms should keep visible VM rows aligned with the Azure VMs the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.VMAssets {
		row := findVMRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-vm-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible VM row for id %q", label, truth.ID),
				"vms asset visibility or Azure-backed validation context",
				"vms should keep visible Azure VM assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkString := func(field string, expected string, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced VM id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkIPList := func(field string, expected []string, likelySeam string, expectedOutcome string) {
			expectedSet := normalizePlainStringSet(expected)
			observedValues := rowStringList(row, field)
			observedSet := normalizePlainStringSet(observedValues)
			if len(expectedSet) == len(observedSet) {
				matches := true
				for expectedValue := range expectedSet {
					if _, ok := observedSet[expectedValue]; !ok {
						matches = false
						break
					}
				}
				if matches {
					return
				}
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced VM id %q with %s %v, but Azure reports %v", label, truth.ID, field, observedValues, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkResourceIDList := func(field string, expected []string, likelySeam string, expectedOutcome string) {
			observedValues := rowStringList(row, field)
			observedSet := normalizeStringSet(observedValues)
			for _, expectedValue := range expected {
				if _, ok := observedSet[normalizeResourceID(expectedValue)]; ok {
					continue
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s surfaced VM id %q with %s %v, but Azure reports %v", label, truth.ID, field, observedValues, expected),
					likelySeam,
					expectedOutcome,
				))
				return
			}
			if len(expected) != len(observedSet) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s surfaced VM id %q with %s %v, but Azure reports %v", label, truth.ID, field, observedValues, expected),
					likelySeam,
					expectedOutcome,
				))
			}
		}

		checkString("name", truth.Name, "vms naming or Azure-backed validation context", "vms should keep the VM name aligned with the Azure asset it is summarizing")
		checkString("resource_group", truth.ResourceGroup, "vms resource-group rendering or Azure-backed validation context", "vms should keep the resource group aligned with the Azure VM it is summarizing")
		checkString("location", truth.Location, "vms location rendering or Azure-backed validation context", "vms should keep the VM location aligned with the Azure asset it is summarizing")
		checkString("power_state", truth.PowerState, "vms power-state rendering or Azure-backed validation context", "vms should keep the VM power state aligned with the Azure asset it is summarizing")
		checkString("vm_type", truth.VMType, "vms type rendering or Azure-backed validation context", "vms should keep the VM type aligned with the Azure asset it is summarizing")
		checkIPList("public_ips", truth.PublicIPs, "vms public IP rendering or Azure-backed validation context", "vms should keep public IPs aligned with the Azure VM it is summarizing")
		checkIPList("private_ips", truth.PrivateIPs, "vms private IP rendering or Azure-backed validation context", "vms should keep private IPs aligned with the Azure VM it is summarizing")
		checkResourceIDList("nic_ids", truth.NICIDs, "vms NIC attachment rendering or Azure-backed validation context", "vms should keep NIC IDs aligned with the Azure VM it is summarizing")
		checkResourceIDList("identity_ids", truth.IdentityIDs, "vms identity rendering or Azure-backed validation context", "vms should keep visible managed identity IDs aligned with the Azure VM it is summarizing")

		if len(truth.PublicIPs) == 0 || len(truth.IdentityIDs) == 0 {
			continue
		}

		findingID := "vm-public-identity-" + truth.ID
		finding := findVMFindingByID(payload, findingID)
		if finding == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-public-identity-finding-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not emit the expected public-with-identity finding for VM id %q", label, truth.ID),
				"vms finding derivation or Azure-backed validation context",
				"vms should emit a public-with-identity finding when a visible VM has both public IP exposure and attached identity IDs",
			))
			continue
		}

		expectedRelatedIDs := append([]string{truth.ID}, truth.IdentityIDs...)
		observedRelatedIDs := normalizeStringSet(rowStringList(finding, "related_ids"))
		for _, expectedRelatedID := range expectedRelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-public-identity-related-ids-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced VM finding %q with related_ids %v, but Azure-backed expectation includes %q", label, findingID, rowStringList(finding, "related_ids"), expectedRelatedID),
				"vms finding linkage or Azure-backed validation context",
				"vms public-with-identity findings should keep related_ids aligned with the VM and its visible identity IDs",
			))
			break
		}
	}

	return findings
}

func validateVMSSPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveVMSSContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "vmss" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-vmss-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live vmss context artifact",
			"lab runner vmss context capture",
			"vmss validation should compare the tool payload against recorded Azure VM scale set truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["vmss_assets"].([]any)
	if len(rows) != len(context.VMSSAssets) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d vmss rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.VMSSAssets)),
			"vmss row selection or Azure-backed validation context",
			"vmss should keep visible scale-set rows aligned with the Azure VM scale sets the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.VMSSAssets {
		row := findVMSSRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-vmss-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible VM scale set row for id %q", label, truth.ID),
				"vmss asset visibility or Azure-backed validation context",
				"vmss should keep visible Azure VM scale set assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkString := func(field string, expected string, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced VMSS id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkInt := func(field string, expected int, likelySeam string, expectedOutcome string) {
			observed, _ := row[field].(float64)
			if int(observed) == expected {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced VMSS id %q with %s %d, but Azure reports %d", label, truth.ID, field, int(observed), expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkBoolPtr := func(field string, expected *bool, likelySeam string, expectedOutcome string) {
			if expected == nil {
				return
			}
			observed, ok := row[field].(bool)
			if ok && observed == *expected {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced VMSS id %q with %s %v, but Azure reports %v", label, truth.ID, field, row[field], *expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkStringFold := func(field string, expected string, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if strings.EqualFold(strings.TrimSpace(observed), strings.TrimSpace(expected)) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced VMSS id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkString("name", truth.Name, "vmss naming or Azure-backed validation context", "vmss should keep the scale-set name aligned with the Azure asset it is summarizing")
		checkStringFold("resource_group", truth.ResourceGroup, "vmss resource-group rendering or Azure-backed validation context", "vmss should keep the resource group aligned with the Azure scale set it is summarizing")
		checkString("location", truth.Location, "vmss location rendering or Azure-backed validation context", "vmss should keep the scale-set location aligned with the Azure asset it is summarizing")
		checkString("sku_name", truth.SKUName, "vmss sku rendering or Azure-backed validation context", "vmss should keep the scale-set SKU aligned with the Azure asset it is summarizing")
		checkString("identity_type", truth.IdentityType, "vmss identity typing or Azure-backed validation context", "vmss should keep scale-set identity typing aligned with the Azure configuration it is summarizing")
		checkString("orchestration_mode", truth.OrchestrationMode, "vmss orchestration rendering or Azure-backed validation context", "vmss should keep orchestration mode aligned with the Azure scale set it is summarizing")
		checkString("upgrade_mode", truth.UpgradeMode, "vmss upgrade rendering or Azure-backed validation context", "vmss should keep upgrade mode aligned with the Azure scale set it is summarizing")
		checkBoolPtr("single_placement_group", truth.SinglePlacementGroup, "vmss placement rendering or Azure-backed validation context", "vmss should keep single-placement-group posture aligned with the Azure scale set it is summarizing")
		checkBoolPtr("overprovision", truth.Overprovision, "vmss capacity rendering or Azure-backed validation context", "vmss should keep overprovision posture aligned with the Azure scale set it is summarizing")
		checkInt("nic_configuration_count", truth.NICConfigurationCount, "vmss network rendering or Azure-backed validation context", "vmss should keep NIC configuration counts aligned with the Azure scale set it is summarizing")
		checkInt("public_ip_configuration_count", truth.PublicIPConfigurationCount, "vmss frontend rendering or Azure-backed validation context", "vmss should keep public IP configuration counts aligned with the Azure scale set it is summarizing")
		checkInt("load_balancer_backend_pool_count", truth.LoadBalancerBackendPoolCount, "vmss frontend rendering or Azure-backed validation context", "vmss should keep load balancer backend pool counts aligned with the Azure scale set it is summarizing")
		checkInt("inbound_nat_pool_count", truth.InboundNATPoolCount, "vmss frontend rendering or Azure-backed validation context", "vmss should keep inbound NAT pool counts aligned with the Azure scale set it is summarizing")
		checkInt("application_gateway_backend_pool_count", truth.ApplicationGatewayBackendPoolCount, "vmss frontend rendering or Azure-backed validation context", "vmss should keep application gateway backend pool counts aligned with the Azure scale set it is summarizing")

		if truth.InstanceCount != nil {
			checkInt("instance_count", *truth.InstanceCount, "vmss capacity rendering or Azure-backed validation context", "vmss should keep configured instance counts aligned with the Azure scale set it is summarizing")
		}

		observedSubnetIDs := normalizeStringSet(rowStringList(row, "subnet_ids"))
		for _, expectedSubnetID := range truth.SubnetIDs {
			if _, ok := observedSubnetIDs[normalizeResourceID(expectedSubnetID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-subnet-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced VMSS id %q with subnet_ids %v, but Azure reports %v", label, truth.ID, rowStringList(row, "subnet_ids"), truth.SubnetIDs),
				"vmss subnet rendering or Azure-backed validation context",
				"vmss should keep subnet references aligned with the Azure scale set network configuration it is summarizing",
			))
			break
		}

		observedIdentityIDs := normalizeStringSet(rowStringList(row, "identity_ids"))
		for _, expectedIdentityID := range truth.IdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced VMSS id %q with identity_ids %v, but Azure reports %v", label, truth.ID, rowStringList(row, "identity_ids"), truth.IdentityIDs),
				"vmss identity rendering or Azure-backed validation context",
				"vmss should preserve the visible identity IDs Azure currently shows on visible scale sets",
			))
			break
		}
	}

	return findings
}
