package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLiveRunAcceptsDNSAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-dns-pass-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-dns-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "dns",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/dns/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "dns", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"dns_zones":[{"id":"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/dnszones/example.net","name":"example.net","resource_group":"rg-network","location":"global","zone_kind":"public","record_set_count":3,"max_record_set_count":10000,"name_servers":["ns1-01.azure-dns.com.","ns2-01.azure-dns.net."],"related_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/dnszones/example.net"],"summary":"summary"},{"id":"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net","name":"privatelink.blob.core.windows.net","resource_group":"rg-network","location":"global","zone_kind":"private","record_set_count":4,"max_record_set_count":25000,"name_servers":[],"linked_virtual_network_count":1,"registration_virtual_network_count":0,"private_endpoint_reference_count":1,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net","/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateEndpoints/pe-storage"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"dns","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	publicRecordCount := 3
	publicMaxRecordCount := 10000
	privateRecordCount := 4
	privateMaxRecordCount := 25000
	privateLinkedVNets := 1
	privateRegistrationVNets := 0
	privateEndpointReferences := 1
	if err := WriteJSON(filepath.Join(payloadDir, "live-dns-context.json"), liveDNSContextArtifact{
		DNSZones: []liveDNSTruth{
			{
				ID:                "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/dnszones/example.net",
				Name:              "example.net",
				ResourceGroup:     "rg-network",
				Location:          "global",
				ZoneKind:          "public",
				RecordSetCount:    &publicRecordCount,
				MaxRecordSetCount: &publicMaxRecordCount,
				NameServers:       []string{"ns1-01.azure-dns.com.", "ns2-01.azure-dns.net."},
				RelatedIDs:        []string{"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/dnszones/example.net"},
			},
			{
				ID:                              "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net",
				Name:                            "privatelink.blob.core.windows.net",
				ResourceGroup:                   "rg-network",
				Location:                        "global",
				ZoneKind:                        "private",
				RecordSetCount:                  &privateRecordCount,
				MaxRecordSetCount:               &privateMaxRecordCount,
				NameServers:                     []string{},
				LinkedVirtualNetworkCount:       &privateLinkedVNets,
				RegistrationVirtualNetworkCount: &privateRegistrationVNets,
				PrivateEndpointReferenceCount:   &privateEndpointReferences,
				RelatedIDs: []string{
					"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net",
					"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateEndpoints/pe-storage",
				},
			},
		},
	}); err != nil {
		t.Fatalf("write dns context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected dns seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsDNSPrivateEndpointReferenceDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-dns-private-endpoint-drift-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-dns-private-endpoint-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "dns",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/dns/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "dns", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"dns_zones":[{"id":"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net","name":"privatelink.blob.core.windows.net","resource_group":"rg-network","location":"global","zone_kind":"private","record_set_count":4,"max_record_set_count":25000,"linked_virtual_network_count":1,"registration_virtual_network_count":0,"private_endpoint_reference_count":0,"related_ids":["/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"],"summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"dns","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	privateRecordCount := 4
	privateMaxRecordCount := 25000
	privateLinkedVNets := 1
	privateRegistrationVNets := 0
	privateEndpointReferences := 1
	if err := WriteJSON(filepath.Join(payloadDir, "live-dns-context.json"), liveDNSContextArtifact{
		DNSZones: []liveDNSTruth{
			{
				ID:                              "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net",
				Name:                            "privatelink.blob.core.windows.net",
				ResourceGroup:                   "rg-network",
				Location:                        "global",
				ZoneKind:                        "private",
				RecordSetCount:                  &privateRecordCount,
				MaxRecordSetCount:               &privateMaxRecordCount,
				NameServers:                     []string{},
				LinkedVirtualNetworkCount:       &privateLinkedVNets,
				RegistrationVirtualNetworkCount: &privateRegistrationVNets,
				PrivateEndpointReferenceCount:   &privateEndpointReferences,
				RelatedIDs: []string{
					"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net",
					"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateEndpoints/pe-storage",
				},
			},
		},
	}); err != nil {
		t.Fatalf("write dns context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected dns private endpoint drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "private_endpoint_reference_count") && strings.Contains(finding.Summary, "but Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected dns private endpoint drift finding, got %#v", summary.Findings)
	}
}

func TestPrivateEndpointDNSZoneConfigsAcceptsAzureCLITopLevelShape(t *testing.T) {
	raw := []byte(`{
		"name":"keyvault-zone-group",
		"privateDnsZoneConfigs":[
			{
				"name":"privatelink.vaultcore.azure.net",
				"privateDnsZoneId":"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
			}
		]
	}`)

	group := azPrivateEndpointDNSZoneGroup{}
	if err := json.Unmarshal(raw, &group); err != nil {
		t.Fatalf("unmarshal zone group: %v", err)
	}

	configs := privateEndpointDNSZoneConfigs(group)
	if len(configs) != 1 {
		t.Fatalf("expected one dns zone config, got %#v", configs)
	}
	if got := configs[0].PrivateDNSZoneID; got != "/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net" {
		t.Fatalf("expected top-level privateDnsZoneId to survive parsing, got %q", got)
	}
}

func TestValidateLiveRunAcceptsEndpointsAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-endpoints-pass-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-endpoints-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "endpoints",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/endpoints/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "endpoints", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"endpoints":[{"endpoint":"52.165.253.164","endpoint_type":"ip","exposure_family":"public-ip","ingress_path":"direct-vm-ip","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01"],"source_asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","source_asset_kind":"VM","source_asset_name":"vm-web-01","summary":"summary"},{"endpoint":"func-orders.azurewebsites.net","endpoint_type":"hostname","exposure_family":"managed-web-hostname","ingress_path":"azure-functions-default-hostname","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders"],"source_asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders","source_asset_kind":"FunctionApp","source_asset_name":"func-orders","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"endpoints","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-endpoints-context.json"), liveEndpointsContextArtifact{
		Endpoints: []liveEndpointTruth{
			{
				Endpoint:        "52.165.253.164",
				EndpointType:    "ip",
				ExposureFamily:  "public-ip",
				IngressPath:     "direct-vm-ip",
				SourceAssetID:   "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
				SourceAssetKind: "VM",
				SourceAssetName: "vm-web-01",
			},
			{
				Endpoint:        "func-orders.azurewebsites.net",
				EndpointType:    "hostname",
				ExposureFamily:  "managed-web-hostname",
				IngressPath:     "azure-functions-default-hostname",
				SourceAssetID:   "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders",
				SourceAssetKind: "FunctionApp",
				SourceAssetName: "func-orders",
			},
		},
	}); err != nil {
		t.Fatalf("write endpoints context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected endpoints seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsEndpointsIngressDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-endpoints-ingress-drift-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-endpoints-ingress-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{
			{
				SurfaceKind: "commands",
				SurfaceName: "endpoints",
				Viewpoint:   "admin",
				Status:      "pass",
				PayloadPath: "artifacts/payloads/commands/endpoints/admin/stdout.json",
			},
		},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "endpoints", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"endpoints":[{"endpoint":"func-orders.azurewebsites.net","endpoint_type":"hostname","exposure_family":"managed-web-hostname","ingress_path":"azurewebsites-default-hostname","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders"],"source_asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders","source_asset_kind":"FunctionApp","source_asset_name":"func-orders","summary":"summary"}],"findings":[],"issues":[],"metadata":{"command":"endpoints","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-endpoints-context.json"), liveEndpointsContextArtifact{
		Endpoints: []liveEndpointTruth{
			{
				Endpoint:        "func-orders.azurewebsites.net",
				EndpointType:    "hostname",
				ExposureFamily:  "managed-web-hostname",
				IngressPath:     "azure-functions-default-hostname",
				SourceAssetID:   "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Web/sites/func-orders",
				SourceAssetKind: "FunctionApp",
				SourceAssetName: "func-orders",
			},
		},
	}); err != nil {
		t.Fatalf("write endpoints context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected endpoints ingress drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "ingress_path") && strings.Contains(finding.Summary, "azure-functions-default-hostname") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected endpoints ingress drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsNetworkEffectiveAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-network-effective-pass-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-network-effective-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "network-effective",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/network-effective/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "network-effective", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"effective_exposures":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","asset_name":"vm-web-01","endpoint":"52.165.253.164","endpoint_type":"ip","effective_exposure":"high","internet_exposed_ports":["TCP/22"],"constrained_ports":[],"observed_paths":["Internet via subnet-nsg:rg-network/nsg-workload/allow-ssh"],"related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/vm-web-01-nic","/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/networkSecurityGroups/nsg-workload"],"summary":"Asset 'vm-web-01' endpoint 52.165.253.164 has internet-facing allow evidence on TCP/22. Treat this as visible Azure network triage signal, not proof of full effective reachability."},{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web","asset_name":"aci-web","endpoint":"172.168.227.147","endpoint_type":"ip","effective_exposure":"low","internet_exposed_ports":[],"constrained_ports":[],"observed_paths":[],"related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"summary":"Asset 'aci-web' endpoint 172.168.227.147 is visible as a public IP path, but no inbound-rule evidence was surfaced from the current read path. Treat this as a low-confidence triage clue rather than proof of exposure."}],"findings":[],"issues":[],"metadata":{"command":"network-effective","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-network-effective-context.json"), liveNetworkEffectiveContextArtifact{
		EffectiveExposures: []liveNetworkEffectiveTruth{
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
				AssetName:            "vm-web-01",
				Endpoint:             "52.165.253.164",
				EndpointType:         "ip",
				EffectiveExposure:    "high",
				InternetExposedPorts: []string{"TCP/22"},
				ConstrainedPorts:     []string{},
				ObservedPaths:        []string{"Internet via subnet-nsg:rg-network/nsg-workload/allow-ssh"},
				RelatedIDs: []string{
					"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
					"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/vm-web-01-nic",
					"/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/networkSecurityGroups/nsg-workload",
				},
				SummaryBoundary: "not proof of full effective reachability",
			},
			{
				AssetID:              "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web",
				AssetName:            "aci-web",
				Endpoint:             "172.168.227.147",
				EndpointType:         "ip",
				EffectiveExposure:    "low",
				InternetExposedPorts: []string{},
				ConstrainedPorts:     []string{},
				ObservedPaths:        []string{},
				RelatedIDs: []string{
					"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web",
					"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app",
				},
				SummaryBoundary: "low-confidence triage clue rather than proof of exposure",
			},
		},
	}); err != nil {
		t.Fatalf("write network-effective context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected network-effective seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsNetworkEffectiveRelatedIDDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-network-effective-related-id-drift-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-network-effective-related-id-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "network-effective",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/network-effective/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "network-effective", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"effective_exposures":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web","asset_name":"aci-web","endpoint":"172.168.227.147","endpoint_type":"ip","effective_exposure":"low","internet_exposed_ports":[],"constrained_ports":[],"observed_paths":[],"related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web"],"summary":"Asset 'aci-web' endpoint 172.168.227.147 is visible as a public IP path, but no inbound-rule evidence was surfaced from the current read path. Treat this as a low-confidence triage clue rather than proof of exposure."}],"findings":[],"issues":[],"metadata":{"command":"network-effective","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-network-effective-context.json"), liveNetworkEffectiveContextArtifact{
		EffectiveExposures: []liveNetworkEffectiveTruth{{
			AssetID:           "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web",
			AssetName:         "aci-web",
			Endpoint:          "172.168.227.147",
			EndpointType:      "ip",
			EffectiveExposure: "low",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ContainerInstance/containerGroups/aci-web",
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app",
			},
			SummaryBoundary: "low-confidence triage clue rather than proof of exposure",
		}},
	}); err != nil {
		t.Fatalf("write network-effective context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected network-effective related_ids drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "related_ids") && strings.Contains(finding.Summary, "ua-app") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected network-effective related_ids drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsNetworkPortsReducedViewAzureContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-network-ports-reduced-pass-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-network-ports-reduced-pass-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "network-ports",
			Viewpoint:   "lower-privilege",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/network-ports/lower-privilege/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "network-ports", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"network_ports":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","asset_name":"vm-web-01","endpoint":"52.165.253.164","protocol":"any","port":"any","allow_source_summary":"no Azure NSG visible on NIC or subnet","exposure_confidence":"low","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"summary":"Asset 'vm-web-01' endpoint 52.165.253.164 is visible via a public NIC path, but no NIC or subnet NSG was visible from the current Azure read path. Treat this as a low-confidence triage clue rather than proof of reachable inbound ports."}],"findings":[],"issues":[{"code":"collection_error","scope":"subnets[/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-workload/subnets/workload]","message":"AuthorizationFailed"}],"metadata":{"command":"network-ports","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-network-ports-context.json"), liveNetworkPortsContextArtifact{
		NetworkPorts: []liveNetworkPortTruth{{
			AssetID:            "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			AssetName:          "vm-web-01",
			Endpoint:           "52.165.253.164",
			Protocol:           "any",
			Port:               "any",
			AllowSourceSummary: "no Azure NSG visible on NIC or subnet",
			ExposureConfidence: "low",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01",
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app",
			},
		}},
	}); err != nil {
		t.Fatalf("write network-ports context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected network-ports reduced-view seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsNetworkPortsReducedViewStrongRowDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-network-ports-reduced-strong-drift-test",
		StartedAt:           UTCTimestamp(),
		FinishedAt:          UTCTimestamp(),
		DemoCaptureExpected: false,
		Scope:               RunScope{},
		SurfaceResults:      RunSurfaceResults{},
		Artifacts:           map[string]ArtifactRecord{},
		FinalOutcome:        "pass",
		Findings:            []Finding{},
		Teardown:            TeardownRecord{Status: "standing-resource-recorded", Notes: "placeholder"},
	}
	if err := WriteJSON(filepath.Join(runDir, "run-result.json"), runResult); err != nil {
		t.Fatalf("write run-result: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "artifacts"), 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := WriteJSON(filepath.Join(runDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      "live-network-ports-reduced-strong-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "network-ports",
			Viewpoint:   "lower-privilege",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/network-ports/lower-privilege/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "network-ports", "lower-privilege")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"network_ports":[{"asset_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","asset_name":"vm-web-01","endpoint":"52.165.253.164","protocol":"TCP","port":"22","allow_source_summary":"Internet via subnet-nsg:rg-network/nsg-workload/allow-ssh-internet","exposure_confidence":"high","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01","/subscriptions/sub-123/resourceGroups/rg-network/providers/Microsoft.Network/networkSecurityGroups/nsg-workload","/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app"],"summary":"Asset 'vm-web-01' endpoint 52.165.253.164 has visible allow evidence on TCP/22 from Internet."}],"findings":[],"issues":[],"metadata":{"command":"network-ports","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-network-ports-context.json"), liveNetworkPortsContextArtifact{
		NetworkPorts: []liveNetworkPortTruth{{
			AssetID:            "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			AssetName:          "vm-web-01",
			Endpoint:           "52.165.253.164",
			Protocol:           "any",
			Port:               "any",
			AllowSourceSummary: "no Azure NSG visible on NIC or subnet",
			ExposureConfidence: "low",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Network/networkInterfaces/nic-web-01",
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-app",
			},
		}},
	}); err != nil {
		t.Fatalf("write network-ports context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected network-ports reduced-view drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "did not surface the Azure-visible network-ports row") &&
			strings.Contains(finding.Summary, `protocol "any" port "any"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected reduced-view network-ports row drift finding, got %#v", summary.Findings)
	}
}
