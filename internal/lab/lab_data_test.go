package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLiveRunFlagsStoragePublicFindingDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-storage-public-finding-drift-test",
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
		RunID:      "live-storage-public-finding-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "storage",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/storage/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "storage", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"storage_assets":[{"allow_shared_key_access":true,"dns_endpoint_type":"Standard","https_traffic_only_enabled":true,"id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","is_hns_enabled":false,"is_sftp_enabled":false,"location":"centralus","minimum_tls_version":"TLS1_2","name":"stpublic","network_default_action":"Allow","nfs_v3_enabled":false,"private_endpoint_enabled":false,"public_access":true,"public_network_access":"Enabled","resource_group":"rg-data"},{"allow_shared_key_access":true,"dns_endpoint_type":"Standard","https_traffic_only_enabled":true,"id":"/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stprivate","is_hns_enabled":false,"is_sftp_enabled":false,"location":"centralus","minimum_tls_version":"TLS1_2","name":"stprivate","network_default_action":"Deny","nfs_v3_enabled":false,"private_endpoint_enabled":true,"public_access":false,"public_network_access":"Enabled","resource_group":"rg-data"}],"findings":[{"description":"Storage account 'stpublic' default firewall action is Allow. Review allowed network sources and private endpoint posture.","id":"storage-firewall-open-/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic","related_ids":["/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic"],"severity":"medium","title":"Storage account network default action is Allow"}],"issues":[],"metadata":{"command":"storage","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	sharedKeyEnabled := true
	httpsOnly := true
	hnsDisabled := false
	sftpDisabled := false
	nfsDisabled := false
	if err := WriteJSON(filepath.Join(payloadDir, "live-storage-context.json"), liveStorageContextArtifact{
		StorageAssets: []liveStorageTruth{
			{
				AllowSharedKeyAccess:    &sharedKeyEnabled,
				DNSEndpointType:         "Standard",
				HTTPSTrafficOnlyEnabled: &httpsOnly,
				ID:                      "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic",
				IsHNSEnabled:            &hnsDisabled,
				IsSFTPEnabled:           &sftpDisabled,
				Location:                "centralus",
				MinimumTLSVersion:       "TLS1_2",
				Name:                    "stpublic",
				NetworkDefaultAction:    "Allow",
				NFSV3Enabled:            &nfsDisabled,
				PrivateEndpointEnabled:  false,
				PublicAccess:            true,
				PublicNetworkAccess:     "Enabled",
				ResourceGroup:           "rg-data",
			},
			{
				AllowSharedKeyAccess:    &sharedKeyEnabled,
				DNSEndpointType:         "Standard",
				HTTPSTrafficOnlyEnabled: &httpsOnly,
				ID:                      "/subscriptions/sub-123/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stprivate",
				IsHNSEnabled:            &hnsDisabled,
				IsSFTPEnabled:           &sftpDisabled,
				Location:                "centralus",
				MinimumTLSVersion:       "TLS1_2",
				Name:                    "stprivate",
				NetworkDefaultAction:    "Deny",
				NFSV3Enabled:            &nfsDisabled,
				PrivateEndpointEnabled:  true,
				PublicAccess:            false,
				PublicNetworkAccess:     "Enabled",
				ResourceGroup:           "rg-data",
			},
		},
	}); err != nil {
		t.Fatalf("write storage context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected storage finding drift, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public-access finding") && strings.Contains(finding.Summary, "public blob access enabled") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected storage public finding drift, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsKeyVaultPublicFindingDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-keyvault-public-finding-drift-test",
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
		RunID:      "live-keyvault-public-finding-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "keyvault",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/keyvault/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "keyvault", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"key_vaults":[{"access_policy_count":2,"enable_rbac_authorization":false,"id":"/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open","location":"centralus","name":"kv-open","network_default_action":"","private_endpoint_enabled":false,"public_network_access":"Enabled","purge_protection_enabled":false,"resource_group":"rg-secrets","sku_name":"standard","soft_delete_enabled":true,"tenant_id":"tenant-123","vault_uri":"https://kv-open.vault.azure.net/"}],"findings":[{"description":"Key Vault 'kv-open' does not have purge protection enabled. Validate whether destructive recovery protections are intentionally absent.","id":"keyvault-purge-protection-disabled-/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open","related_ids":["/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open"],"severity":"medium","title":"Key Vault purge protection is disabled"}],"issues":[],"metadata":{"command":"keyvault","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-keyvault-context.json"), liveKeyVaultContextArtifact{
		KeyVaults: []liveKeyVaultTruth{{
			AccessPolicyCount:       2,
			EnableRBACAuthorization: false,
			ID:                      "/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open",
			Location:                "centralus",
			Name:                    "kv-open",
			NetworkDefaultAction:    "",
			PrivateEndpointEnabled:  false,
			PublicNetworkAccess:     "Enabled",
			PurgeProtectionEnabled:  false,
			ResourceGroup:           "rg-secrets",
			SKUName:                 "standard",
			SoftDeleteEnabled:       true,
			TenantID:                "tenant-123",
			VaultURI:                "https://kv-open.vault.azure.net/",
		}},
	}); err != nil {
		t.Fatalf("write keyvault context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected keyvault finding drift, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public-network-open finding") && strings.Contains(finding.Summary, "open public posture") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected keyvault public finding drift, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunAcceptsMatchingKeyVaultContext(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-keyvault-match-test",
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
		RunID:      "live-keyvault-match-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "keyvault",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/keyvault/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "keyvault", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"key_vaults":[{"access_policy_count":2,"enable_rbac_authorization":false,"id":"/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open","location":"centralus","name":"kv-open","network_default_action":"","private_endpoint_enabled":false,"public_network_access":"Enabled","purge_protection_enabled":false,"resource_group":"rg-secrets","sku_name":"standard","soft_delete_enabled":true,"tenant_id":"tenant-123","vault_uri":"https://kv-open.vault.azure.net/"},{"access_policy_count":0,"enable_rbac_authorization":true,"id":"/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-private","location":"centralus","name":"kv-private","network_default_action":"Deny","private_endpoint_enabled":true,"public_network_access":"Disabled","purge_protection_enabled":true,"resource_group":"rg-secrets","sku_name":"premium","soft_delete_enabled":true,"tenant_id":"tenant-123","vault_uri":"https://kv-private.vault.azure.net/"}],"findings":[{"description":"Key Vault 'kv-open' has public network access enabled, Azure omitted the network ACL object, and no private endpoint is visible. Azure can return that shape for a fully open vault. Review whether that secret-management surface is intentionally internet reachable.","id":"keyvault-public-network-open-/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open","related_ids":["/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open"],"severity":"high","title":"Key Vault is broadly reachable on the public network"},{"description":"Key Vault 'kv-open' does not have purge protection enabled. Validate whether destructive recovery protections are intentionally absent.","id":"keyvault-purge-protection-disabled-/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open","related_ids":["/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open"],"severity":"medium","title":"Key Vault purge protection is disabled"}],"issues":[],"metadata":{"command":"keyvault","generated_at":"2026-04-21T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-keyvault-context.json"), liveKeyVaultContextArtifact{
		KeyVaults: []liveKeyVaultTruth{
			{
				AccessPolicyCount:       2,
				EnableRBACAuthorization: false,
				ID:                      "/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-open",
				Location:                "centralus",
				Name:                    "kv-open",
				NetworkDefaultAction:    "",
				PrivateEndpointEnabled:  false,
				PublicNetworkAccess:     "Enabled",
				PurgeProtectionEnabled:  false,
				ResourceGroup:           "rg-secrets",
				SKUName:                 "standard",
				SoftDeleteEnabled:       true,
				TenantID:                "tenant-123",
				VaultURI:                "https://kv-open.vault.azure.net/",
			},
			{
				AccessPolicyCount:       0,
				EnableRBACAuthorization: true,
				ID:                      "/subscriptions/sub-123/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-private",
				Location:                "centralus",
				Name:                    "kv-private",
				NetworkDefaultAction:    "Deny",
				PrivateEndpointEnabled:  true,
				PublicNetworkAccess:     "Disabled",
				PurgeProtectionEnabled:  true,
				ResourceGroup:           "rg-secrets",
				SKUName:                 "premium",
				SoftDeleteEnabled:       true,
				TenantID:                "tenant-123",
				VaultURI:                "https://kv-private.vault.azure.net/",
			},
		},
	}); err != nil {
		t.Fatalf("write keyvault context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount != 0 {
		t.Fatalf("expected matching keyvault seam to pass cleanly, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsSnapshotsDisksPublicNetworkDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-snapshots-disks-public-network-drift-test",
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
		RunID:      "live-snapshots-disks-public-network-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "snapshots-disks",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/snapshots-disks/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "snapshots-disks", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"snapshot_disk_assets":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/disks/vm-web-01-os","name":"vm-web-01-os","asset_kind":"disk","resource_group":"rg-workload","location":"centralus","disk_role":"os-disk","attachment_state":"attached","attached_to_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01","attached_to_name":"vm-web-01","os_type":"Linux","network_access_policy":"AllowAll","public_network_access":"Disabled","disk_access_id":null,"max_shares":null,"encryption_type":"EncryptionAtRestWithPlatformKey","disk_encryption_set_id":null,"summary":"summary","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01"]}],"findings":[],"issues":[],"metadata":{"command":"snapshots-disks","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := WriteJSON(filepath.Join(payloadDir, "live-snapshots-disks-context.json"), liveSnapshotsDisksContextArtifact{
		SnapshotDiskAssets: []liveSnapshotDiskTruth{{
			AssetKind:           "disk",
			AttachedToID:        "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			AttachedToName:      "vm-web-01",
			AttachmentState:     "attached",
			EncryptionType:      "EncryptionAtRestWithPlatformKey",
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/disks/vm-web-01-os",
			Location:            "centralus",
			Name:                "vm-web-01-os",
			NetworkAccessPolicy: "AllowAll",
			OSType:              "Linux",
			PublicNetworkAccess: "Enabled",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/virtualMachines/vm-web-01",
			},
			ResourceGroup: "rg-workload",
		}},
	}); err != nil {
		t.Fatalf("write snapshots-disks context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected snapshots-disks public network drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "public_network_access") && strings.Contains(finding.Summary, "Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected snapshots-disks public network drift finding, got %#v", summary.Findings)
	}
}

func TestValidateLiveRunFlagsSnapshotsDisksSourceResourceDrift(t *testing.T) {
	runDir := t.TempDir()
	runResult := RunResult{
		RunID:               "live-snapshots-disks-source-resource-drift-test",
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
		RunID:      "live-snapshots-disks-source-resource-drift-test",
		EntryCount: 1,
		Entries: []CommandLogEntry{{
			SurfaceKind: "commands",
			SurfaceName: "snapshots-disks",
			Viewpoint:   "admin",
			Status:      "pass",
			PayloadPath: "artifacts/payloads/commands/snapshots-disks/admin/stdout.json",
		}},
	}); err != nil {
		t.Fatalf("write command-log: %v", err)
	}

	payloadDir := filepath.Join(runDir, "artifacts", "payloads", "commands", "snapshots-disks", "admin")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		t.Fatalf("mkdir payload dir: %v", err)
	}
	payload := `{"snapshot_disk_assets":[{"id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/snapshots/vm-web-01-os-snap","name":"vm-web-01-os-snap","asset_kind":"snapshot","resource_group":"rg-workload","location":"centralus","attachment_state":"snapshot","source_resource_id":"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/disks/vm-api-01-os","source_resource_name":"vm-api-01-os","source_resource_kind":"disk","os_type":"Linux","incremental":true,"network_access_policy":"AllowPrivate","public_network_access":"Disabled","disk_access_id":null,"max_shares":null,"encryption_type":"EncryptionAtRestWithPlatformKey","disk_encryption_set_id":null,"summary":"summary","related_ids":["/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/disks/vm-api-01-os"]}],"findings":[],"issues":[],"metadata":{"command":"snapshots-disks","generated_at":"2026-04-20T00:00:00Z","schema_version":"1.0.0","subscription_id":"sub-123","tenant_id":"tenant-123"}}`
	if err := os.WriteFile(filepath.Join(payloadDir, "stdout.json"), []byte(payload), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	incremental := true
	if err := WriteJSON(filepath.Join(payloadDir, "live-snapshots-disks-context.json"), liveSnapshotsDisksContextArtifact{
		SnapshotDiskAssets: []liveSnapshotDiskTruth{{
			AssetKind:           "snapshot",
			AttachmentState:     "snapshot",
			EncryptionType:      "EncryptionAtRestWithPlatformKey",
			ID:                  "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/snapshots/vm-web-01-os-snap",
			Incremental:         &incremental,
			Location:            "centralus",
			Name:                "vm-web-01-os-snap",
			NetworkAccessPolicy: "AllowPrivate",
			OSType:              "Linux",
			PublicNetworkAccess: "Disabled",
			RelatedIDs: []string{
				"/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/disks/vm-web-01-os",
			},
			ResourceGroup:      "rg-workload",
			SourceResourceID:   "/subscriptions/sub-123/resourceGroups/rg-workload/providers/Microsoft.Compute/disks/vm-web-01-os",
			SourceResourceKind: "disk",
			SourceResourceName: "vm-web-01-os",
		}},
	}); err != nil {
		t.Fatalf("write snapshots-disks context: %v", err)
	}

	summary, err := ValidateLiveRun(filepath.Join(runDir, "run-result.json"), hoAzureDir)
	if err != nil {
		t.Fatalf("validate live run: %v", err)
	}
	if summary.FindingCount == 0 {
		t.Fatalf("expected snapshots-disks source-resource drift finding, got %#v", summary)
	}
	found := false
	for _, finding := range summary.Findings {
		if strings.Contains(finding.Summary, "source_resource_id") && strings.Contains(finding.Summary, "Azure reports") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected snapshots-disks source-resource drift finding, got %#v", summary.Findings)
	}
}
