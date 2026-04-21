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

const storageValidationAPIVersion = "2025-06-01"
const snapshotsDisksValidationAPIVersion = "2023-04-02"

type liveSnapshotsDisksContextArtifact struct {
	SnapshotDiskAssets []liveSnapshotDiskTruth `json:"snapshot_disk_assets"`
}

type liveSnapshotDiskTruth struct {
	AssetKind           string   `json:"asset_kind"`
	AttachedToID        string   `json:"attached_to_id,omitempty"`
	AttachedToName      string   `json:"attached_to_name,omitempty"`
	AttachmentState     string   `json:"attachment_state"`
	DiskAccessID        string   `json:"disk_access_id,omitempty"`
	DiskEncryptionSetID string   `json:"disk_encryption_set_id,omitempty"`
	EncryptionType      string   `json:"encryption_type,omitempty"`
	ID                  string   `json:"id"`
	Incremental         *bool    `json:"incremental,omitempty"`
	Location            string   `json:"location,omitempty"`
	Name                string   `json:"name"`
	NetworkAccessPolicy string   `json:"network_access_policy,omitempty"`
	OSType              string   `json:"os_type,omitempty"`
	PublicNetworkAccess string   `json:"public_network_access,omitempty"`
	RelatedIDs          []string `json:"related_ids"`
	ResourceGroup       string   `json:"resource_group"`
	SourceResourceID    string   `json:"source_resource_id,omitempty"`
	SourceResourceKind  string   `json:"source_resource_kind,omitempty"`
	SourceResourceName  string   `json:"source_resource_name,omitempty"`
}

type liveStorageContextArtifact struct {
	StorageAssets []liveStorageTruth `json:"storage_assets"`
}

type liveStorageTruth struct {
	AllowSharedKeyAccess    *bool  `json:"allow_shared_key_access,omitempty"`
	DNSEndpointType         string `json:"dns_endpoint_type,omitempty"`
	HTTPSTrafficOnlyEnabled *bool  `json:"https_traffic_only_enabled,omitempty"`
	ID                      string `json:"id"`
	IsHNSEnabled            *bool  `json:"is_hns_enabled,omitempty"`
	IsSFTPEnabled           *bool  `json:"is_sftp_enabled,omitempty"`
	Location                string `json:"location,omitempty"`
	MinimumTLSVersion       string `json:"minimum_tls_version,omitempty"`
	Name                    string `json:"name"`
	NetworkDefaultAction    string `json:"network_default_action,omitempty"`
	NFSV3Enabled            *bool  `json:"nfs_v3_enabled,omitempty"`
	PrivateEndpointEnabled  bool   `json:"private_endpoint_enabled"`
	PublicAccess            bool   `json:"public_access"`
	PublicNetworkAccess     string `json:"public_network_access,omitempty"`
	ResourceGroup           string `json:"resource_group"`
}

type azStorageAccountListResource struct {
	ID            string `json:"id"`
	Location      string `json:"location"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
}

type azStorageAccountShowResource struct {
	ID            string                     `json:"id"`
	Location      string                     `json:"location"`
	Name          string                     `json:"name"`
	Properties    azStorageAccountProperties `json:"properties"`
	ResourceGroup string                     `json:"resourceGroup"`
}

type azStorageAccountProperties struct {
	AllowBlobPublicAccess      bool                              `json:"allowBlobPublicAccess"`
	AllowSharedKeyAccess       *bool                             `json:"allowSharedKeyAccess"`
	DNSEndpointType            string                            `json:"dnsEndpointType"`
	EnableHTTPSTrafficOnly     *bool                             `json:"enableHttpsTrafficOnly"`
	EnableNFSV3                *bool                             `json:"enableNfsV3"`
	IsHNSEnabled               *bool                             `json:"isHnsEnabled"`
	IsNFSV3Enabled             *bool                             `json:"isNfsV3Enabled"`
	IsSFTPEnabled              *bool                             `json:"isSftpEnabled"`
	MinimumTLSVersion          string                            `json:"minimumTlsVersion"`
	NetworkRuleSet             azStorageNetworkRuleSet           `json:"networkRuleSet"`
	PrivateEndpointConnections []azStoragePrivateEndpointConnRef `json:"privateEndpointConnections"`
	PublicNetworkAccess        string                            `json:"publicNetworkAccess"`
	SupportsHTTPSTrafficOnly   *bool                             `json:"supportsHttpsTrafficOnly"`
}

type azStorageNetworkRuleSet struct {
	DefaultAction string `json:"defaultAction"`
}

type azStoragePrivateEndpointConnRef struct {
	ID string `json:"id"`
}

type azManagedDiskListResource struct {
	ID            string `json:"id"`
	Location      string `json:"location"`
	ManagedBy     string `json:"managedBy"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
}

type azManagedDiskShowResource struct {
	ID            string                  `json:"id"`
	Location      string                  `json:"location"`
	ManagedBy     string                  `json:"managedBy"`
	Name          string                  `json:"name"`
	Properties    azManagedDiskProperties `json:"properties"`
	ResourceGroup string                  `json:"resourceGroup"`
}

type azManagedDiskProperties struct {
	DiskAccessID        string                  `json:"diskAccessId"`
	DiskSizeGB          int                     `json:"diskSizeGB"`
	DiskState           string                  `json:"diskState"`
	Encryption          azManagedDiskEncryption `json:"encryption"`
	NetworkAccessPolicy string                  `json:"networkAccessPolicy"`
	OSType              string                  `json:"osType"`
	PublicNetworkAccess string                  `json:"publicNetworkAccess"`
}

type azManagedDiskEncryption struct {
	DiskEncryptionSetID string `json:"diskEncryptionSetId"`
	Type                string `json:"type"`
}

type azSnapshotListResource struct {
	ID            string `json:"id"`
	Location      string `json:"location"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
}

type azSnapshotShowResource struct {
	ID            string               `json:"id"`
	Location      string               `json:"location"`
	Name          string               `json:"name"`
	Properties    azSnapshotProperties `json:"properties"`
	ResourceGroup string               `json:"resourceGroup"`
}

type azSnapshotProperties struct {
	CreationData        azSnapshotCreationData  `json:"creationData"`
	DiskAccessID        string                  `json:"diskAccessId"`
	DiskSizeGB          int                     `json:"diskSizeGB"`
	Encryption          azManagedDiskEncryption `json:"encryption"`
	Incremental         *bool                   `json:"incremental"`
	NetworkAccessPolicy string                  `json:"networkAccessPolicy"`
	OSType              string                  `json:"osType"`
	PublicNetworkAccess string                  `json:"publicNetworkAccess"`
}

type azSnapshotCreationData struct {
	SourceResourceID string `json:"sourceResourceId"`
}

func captureLiveStorageContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Storage/storageAccounts", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (storage validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for storage accounts: %s", strings.TrimSpace(string(listOutput)))
	}
	accounts := []azStorageAccountListResource{}
	if err := json.Unmarshal(listOutput, &accounts); err != nil {
		return fmt.Errorf("parse storage account list output: %w", err)
	}

	if len(accounts) == 0 {
		artifact := liveStorageContextArtifact{StorageAssets: []liveStorageTruth{}}
		if err := WriteJSON(filepath.Join(outdir, "live-storage-context.json"), artifact); err != nil {
			return fmt.Errorf("write live storage context artifact: %w", err)
		}
		return nil
	}

	truths := make([]liveStorageTruth, 0, len(accounts))
	for _, listed := range accounts {
		accountID := strings.TrimSpace(listed.ID)
		if accountID == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", accountID, "--api-version", storageValidationAPIVersion, "--output", "json")
		showOutput, err := runProgressCommand("az resource show (storage validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", accountID, strings.TrimSpace(string(showOutput)))
		}
		account := azStorageAccountShowResource{}
		if err := json.Unmarshal(showOutput, &account); err != nil {
			return fmt.Errorf("parse storage account show output for %s: %w", accountID, err)
		}

		truths = append(truths, liveStorageTruth{
			AllowSharedKeyAccess:    account.Properties.AllowSharedKeyAccess,
			DNSEndpointType:         strings.TrimSpace(account.Properties.DNSEndpointType),
			HTTPSTrafficOnlyEnabled: firstBoolPtr(account.Properties.SupportsHTTPSTrafficOnly, account.Properties.EnableHTTPSTrafficOnly),
			ID:                      accountID,
			IsHNSEnabled:            account.Properties.IsHNSEnabled,
			IsSFTPEnabled:           account.Properties.IsSFTPEnabled,
			Location:                firstNonEmptyString(strings.TrimSpace(account.Location), strings.TrimSpace(listed.Location)),
			MinimumTLSVersion:       strings.TrimSpace(account.Properties.MinimumTLSVersion),
			Name:                    firstNonEmptyString(strings.TrimSpace(account.Name), strings.TrimSpace(listed.Name), resourceNameFromAzureID(accountID), "unknown"),
			NetworkDefaultAction:    strings.TrimSpace(account.Properties.NetworkRuleSet.DefaultAction),
			NFSV3Enabled:            firstBoolPtr(account.Properties.IsNFSV3Enabled, account.Properties.EnableNFSV3),
			PrivateEndpointEnabled:  len(account.Properties.PrivateEndpointConnections) > 0,
			PublicAccess:            account.Properties.AllowBlobPublicAccess,
			PublicNetworkAccess:     strings.TrimSpace(account.Properties.PublicNetworkAccess),
			ResourceGroup:           firstNonEmptyString(strings.TrimSpace(account.ResourceGroup), strings.TrimSpace(listed.ResourceGroup), resourceGroupFromAzureID(accountID)),
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveStorageContextArtifact{StorageAssets: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-storage-context.json"), artifact); err != nil {
		return fmt.Errorf("write live storage context artifact: %w", err)
	}
	return nil
}

func captureLiveSnapshotsDisksContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Compute/disks", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (snapshots-disks validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for managed disks: %s", strings.TrimSpace(string(listOutput)))
	}
	disks := []azManagedDiskListResource{}
	if err := json.Unmarshal(listOutput, &disks); err != nil {
		return fmt.Errorf("parse managed disk list output: %w", err)
	}

	truths := make([]liveSnapshotDiskTruth, 0, len(disks))
	for _, listed := range disks {
		diskID := strings.TrimSpace(listed.ID)
		if diskID == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", diskID, "--api-version", snapshotsDisksValidationAPIVersion, "--output", "json")
		showOutput, err := runProgressCommand("az resource show (snapshots-disks validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", diskID, strings.TrimSpace(string(showOutput)))
		}
		disk := azManagedDiskShowResource{}
		if err := json.Unmarshal(showOutput, &disk); err != nil {
			return fmt.Errorf("parse managed disk show output for %s: %w", diskID, err)
		}

		attachedToID := strings.TrimSpace(firstNonEmptyString(disk.ManagedBy, listed.ManagedBy))
		attachmentState := "detached"
		if attachedToID != "" {
			attachmentState = "attached"
		}
		relatedIDs := compactSortedStrings([]string{
			attachedToID,
			strings.TrimSpace(disk.Properties.DiskAccessID),
			strings.TrimSpace(disk.Properties.Encryption.DiskEncryptionSetID),
		})

		truths = append(truths, liveSnapshotDiskTruth{
			AssetKind:           "disk",
			AttachedToID:        attachedToID,
			AttachedToName:      resourceNameFromAzureID(attachedToID),
			AttachmentState:     attachmentState,
			DiskAccessID:        strings.TrimSpace(disk.Properties.DiskAccessID),
			DiskEncryptionSetID: strings.TrimSpace(disk.Properties.Encryption.DiskEncryptionSetID),
			EncryptionType:      strings.TrimSpace(disk.Properties.Encryption.Type),
			ID:                  diskID,
			Location:            firstNonEmptyString(strings.TrimSpace(disk.Location), strings.TrimSpace(listed.Location)),
			Name:                firstNonEmptyString(strings.TrimSpace(disk.Name), strings.TrimSpace(listed.Name), resourceNameFromAzureID(diskID), "unknown"),
			NetworkAccessPolicy: strings.TrimSpace(disk.Properties.NetworkAccessPolicy),
			OSType:              strings.TrimSpace(disk.Properties.OSType),
			PublicNetworkAccess: strings.TrimSpace(disk.Properties.PublicNetworkAccess),
			RelatedIDs:          relatedIDs,
			ResourceGroup:       firstNonEmptyString(strings.TrimSpace(disk.ResourceGroup), strings.TrimSpace(listed.ResourceGroup), resourceGroupFromAzureID(diskID)),
		})
	}

	snapshotListCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Compute/snapshots", "--output", "json")
	snapshotListOutput, err := runProgressCommand("az resource list (snapshots-disks validation context)", workingDir, env, progressWriter, snapshotListCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for snapshots: %s", strings.TrimSpace(string(snapshotListOutput)))
	}
	snapshots := []azSnapshotListResource{}
	if err := json.Unmarshal(snapshotListOutput, &snapshots); err != nil {
		return fmt.Errorf("parse snapshot list output: %w", err)
	}

	for _, listed := range snapshots {
		snapshotID := strings.TrimSpace(listed.ID)
		if snapshotID == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", snapshotID, "--api-version", snapshotsDisksValidationAPIVersion, "--output", "json")
		showOutput, err := runProgressCommand("az resource show (snapshots-disks validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", snapshotID, strings.TrimSpace(string(showOutput)))
		}
		snapshot := azSnapshotShowResource{}
		if err := json.Unmarshal(showOutput, &snapshot); err != nil {
			return fmt.Errorf("parse snapshot show output for %s: %w", snapshotID, err)
		}

		sourceResourceID := strings.TrimSpace(snapshot.Properties.CreationData.SourceResourceID)
		relatedIDs := compactSortedStrings([]string{
			sourceResourceID,
			strings.TrimSpace(snapshot.Properties.DiskAccessID),
			strings.TrimSpace(snapshot.Properties.Encryption.DiskEncryptionSetID),
		})

		truths = append(truths, liveSnapshotDiskTruth{
			AssetKind:           "snapshot",
			AttachmentState:     "snapshot",
			DiskAccessID:        strings.TrimSpace(snapshot.Properties.DiskAccessID),
			DiskEncryptionSetID: strings.TrimSpace(snapshot.Properties.Encryption.DiskEncryptionSetID),
			EncryptionType:      strings.TrimSpace(snapshot.Properties.Encryption.Type),
			ID:                  snapshotID,
			Incremental:         snapshot.Properties.Incremental,
			Location:            firstNonEmptyString(strings.TrimSpace(snapshot.Location), strings.TrimSpace(listed.Location)),
			Name:                firstNonEmptyString(strings.TrimSpace(snapshot.Name), strings.TrimSpace(listed.Name), resourceNameFromAzureID(snapshotID), "unknown"),
			NetworkAccessPolicy: strings.TrimSpace(snapshot.Properties.NetworkAccessPolicy),
			OSType:              strings.TrimSpace(snapshot.Properties.OSType),
			PublicNetworkAccess: strings.TrimSpace(snapshot.Properties.PublicNetworkAccess),
			RelatedIDs:          relatedIDs,
			ResourceGroup:       firstNonEmptyString(strings.TrimSpace(snapshot.ResourceGroup), strings.TrimSpace(listed.ResourceGroup), resourceGroupFromAzureID(snapshotID)),
			SourceResourceID:    sourceResourceID,
			SourceResourceKind:  snapshotDiskSourceKind(sourceResourceID),
			SourceResourceName:  resourceNameFromAzureID(sourceResourceID),
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveSnapshotsDisksContextArtifact{SnapshotDiskAssets: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-snapshots-disks-context.json"), artifact); err != nil {
		return fmt.Errorf("write live snapshots-disks context artifact: %w", err)
	}
	return nil
}

func snapshotDiskSourceKind(resourceID string) string {
	normalized := strings.ToLower(strings.TrimSpace(resourceID))
	switch {
	case normalized == "":
		return ""
	case strings.Contains(normalized, "/providers/microsoft.compute/disks/"):
		return "disk"
	case strings.Contains(normalized, "/providers/microsoft.compute/snapshots/"):
		return "snapshot"
	default:
		return ""
	}
}

func firstBoolPtr(values ...*bool) *bool {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
