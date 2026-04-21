package lab

import (
	"fmt"
	"strings"
)

func findSnapshotDiskRowByID(payload map[string]any, assetID string) map[string]any {
	rows, _ := payload["snapshot_disk_assets"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(assetID) {
			return rowMap
		}
	}
	return nil
}

func findStorageRowByID(payload map[string]any, storageID string) map[string]any {
	rows, _ := payload["storage_assets"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(storageID) {
			return rowMap
		}
	}
	return nil
}

func storageFindingByID(payload map[string]any, findingID string) map[string]any {
	rows, _ := payload["findings"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if strings.TrimSpace(rowID) == strings.TrimSpace(findingID) {
			return rowMap
		}
	}
	return nil
}

func validateStoragePayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveStorageContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "storage" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-storage-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live storage context artifact",
			"lab runner storage context capture",
			"storage validation should compare the tool payload against recorded Azure storage truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["storage_assets"].([]any)
	if len(rows) != len(context.StorageAssets) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d storage rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.StorageAssets)),
			"storage row selection or Azure-backed validation context",
			"storage should keep visible storage-account rows aligned with the Azure storage accounts the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.StorageAssets {
		row := findStorageRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-storage-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible storage row for id %q", label, truth.ID),
				"storage asset visibility or Azure-backed validation context",
				"storage should keep visible Azure storage accounts visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkString := func(field string, expected string, equalFold bool, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if equalFold {
				if strings.EqualFold(strings.TrimSpace(observed), strings.TrimSpace(expected)) {
					return
				}
			} else if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced storage id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkBool := func(field string, expected bool, likelySeam string, expectedOutcome string) {
			observed := rowBoolPtr(row, field)
			if observed != nil && *observed == expected {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced storage id %q with %s %v, but Azure reports %v", label, truth.ID, field, row[field], expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkBoolPtr := func(field string, expected *bool, likelySeam string, expectedOutcome string) {
			if expected == nil {
				return
			}
			observed := rowBoolPtr(row, field)
			if observed != nil && *observed == *expected {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced storage id %q with %s %v, but Azure reports %v", label, truth.ID, field, row[field], *expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkString("name", truth.Name, false, "storage naming or Azure-backed validation context", "storage should keep the storage-account name aligned with the Azure asset it is summarizing")
		checkString("resource_group", truth.ResourceGroup, true, "storage resource-group rendering or Azure-backed validation context", "storage should keep the resource group aligned with the Azure storage account it is summarizing")
		checkString("location", truth.Location, true, "storage location rendering or Azure-backed validation context", "storage should keep the storage-account location aligned with the Azure asset it is summarizing")
		checkString("public_network_access", truth.PublicNetworkAccess, true, "storage network posture rendering or Azure-backed validation context", "storage should keep public-network posture aligned with the Azure storage account it is summarizing")
		checkString("network_default_action", truth.NetworkDefaultAction, true, "storage firewall rendering or Azure-backed validation context", "storage should keep firewall default-action posture aligned with the Azure storage account it is summarizing")
		checkString("minimum_tls_version", truth.MinimumTLSVersion, false, "storage TLS rendering or Azure-backed validation context", "storage should keep minimum TLS posture aligned with the Azure storage account it is summarizing")
		checkString("dns_endpoint_type", truth.DNSEndpointType, false, "storage endpoint rendering or Azure-backed validation context", "storage should keep endpoint-type cues aligned with the Azure storage account it is summarizing")
		checkBool("public_access", truth.PublicAccess, "storage anonymous-access rendering or Azure-backed validation context", "storage should preserve whether Azure currently allows public blob access on a visible storage account")
		checkBool("private_endpoint_enabled", truth.PrivateEndpointEnabled, "storage private-endpoint rendering or Azure-backed validation context", "storage should preserve whether Azure currently shows a private endpoint connection on a visible storage account")
		checkBoolPtr("allow_shared_key_access", truth.AllowSharedKeyAccess, "storage shared-key rendering or Azure-backed validation context", "storage should keep shared-key posture aligned with the Azure storage account it is summarizing")
		checkBoolPtr("https_traffic_only_enabled", truth.HTTPSTrafficOnlyEnabled, "storage HTTPS-only rendering or Azure-backed validation context", "storage should keep HTTPS-only posture aligned with the Azure storage account it is summarizing")
		checkBoolPtr("is_hns_enabled", truth.IsHNSEnabled, "storage HNS rendering or Azure-backed validation context", "storage should keep HNS posture aligned with the Azure storage account it is summarizing")
		checkBoolPtr("is_sftp_enabled", truth.IsSFTPEnabled, "storage SFTP rendering or Azure-backed validation context", "storage should keep SFTP posture aligned with the Azure storage account it is summarizing")
		checkBoolPtr("nfs_v3_enabled", truth.NFSV3Enabled, "storage NFS rendering or Azure-backed validation context", "storage should keep NFS v3 posture aligned with the Azure storage account it is summarizing")

		publicFindingID := "storage-public-" + truth.ID
		publicFinding := storageFindingByID(payload, publicFindingID)
		if truth.PublicAccess {
			if publicFinding == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-public-finding-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s omitted the shipped public-access finding for storage id %q even though Azure reports public blob access enabled", label, truth.ID),
					"storage findings rendering or Azure-backed validation context",
					"storage should emit the shipped public-access finding whenever Azure shows public blob access enabled",
				))
			}
		} else if publicFinding != nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-public-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted a public-access finding for storage id %q, but Azure does not currently report public blob access enabled", label, truth.ID),
				"storage findings rendering or Azure-backed validation context",
				"storage should not overclaim public blob access when Azure does not show that posture",
			))
		}

		firewallFindingID := "storage-firewall-open-" + truth.ID
		firewallFinding := storageFindingByID(payload, firewallFindingID)
		firewallOpen := strings.EqualFold(strings.TrimSpace(truth.NetworkDefaultAction), "Allow")
		if firewallOpen {
			if firewallFinding == nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-firewall-finding-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s omitted the shipped firewall-open finding for storage id %q even though Azure reports defaultAction Allow", label, truth.ID),
					"storage findings rendering or Azure-backed validation context",
					"storage should emit the shipped firewall-open finding whenever Azure shows defaultAction Allow",
				))
			}
		} else if firewallFinding != nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-unexpected-firewall-finding", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s emitted a firewall-open finding for storage id %q, but Azure does not currently report defaultAction Allow", label, truth.ID),
				"storage findings rendering or Azure-backed validation context",
				"storage should not overclaim firewall-open posture when Azure does not show that default action",
			))
		}
	}

	return findings
}

func validateSnapshotsDisksPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveSnapshotsDisksContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "snapshots-disks" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-snapshots-disks-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live snapshots-disks context artifact",
			"lab runner snapshots-disks context capture",
			"snapshots-disks validation should compare the tool payload against recorded Azure disk and snapshot truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["snapshot_disk_assets"].([]any)
	if len(rows) != len(context.SnapshotDiskAssets) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d snapshots-disks rows, but Azure-backed validation recorded %d visible disk-backed assets", label, len(rows), len(context.SnapshotDiskAssets)),
			"snapshots-disks row selection or Azure-backed validation context",
			"snapshots-disks should keep visible disk-backed rows aligned with the Azure disks and snapshots the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.SnapshotDiskAssets {
		row := findSnapshotDiskRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible snapshots-disks row for id %q", label, truth.ID),
				"snapshots-disks asset visibility or Azure-backed validation context",
				"snapshots-disks should keep visible Azure disks and snapshots visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkString := func(field string, expected string, equalFold bool, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if equalFold {
				if strings.EqualFold(strings.TrimSpace(observed), strings.TrimSpace(expected)) {
					return
				}
			} else if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced snapshots-disks id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkResourceID := func(field string, expected string, likelySeam string, expectedOutcome string) {
			if strings.TrimSpace(expected) == "" {
				return
			}
			observed, _ := row[field].(string)
			if normalizeResourceID(observed) == normalizeResourceID(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced snapshots-disks id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkBoolPtr := func(field string, expected *bool, likelySeam string, expectedOutcome string) {
			if expected == nil {
				return
			}
			observed := rowBoolPtr(row, field)
			if observed != nil && *observed == *expected {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced snapshots-disks id %q with %s %v, but Azure reports %v", label, truth.ID, field, row[field], *expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkString("name", truth.Name, false, "snapshots-disks naming or Azure-backed validation context", "snapshots-disks should keep the disk or snapshot name aligned with the Azure asset it is summarizing")
		checkString("asset_kind", truth.AssetKind, false, "snapshots-disks asset typing or Azure-backed validation context", "snapshots-disks should preserve whether a visible asset is a disk or a snapshot")
		checkString("resource_group", truth.ResourceGroup, true, "snapshots-disks resource-group rendering or Azure-backed validation context", "snapshots-disks should keep the resource group aligned with the Azure asset it is summarizing")
		checkString("location", truth.Location, true, "snapshots-disks location rendering or Azure-backed validation context", "snapshots-disks should keep the asset location aligned with the Azure disk or snapshot it is summarizing")
		checkString("attachment_state", truth.AttachmentState, false, "snapshots-disks attachment rendering or Azure-backed validation context", "snapshots-disks should preserve whether a visible disk is attached or detached")
		checkResourceID("attached_to_id", truth.AttachedToID, "snapshots-disks attachment rendering or Azure-backed validation context", "snapshots-disks should keep the attached workload ID aligned with the Azure disk it is summarizing")
		checkString("attached_to_name", truth.AttachedToName, false, "snapshots-disks attachment rendering or Azure-backed validation context", "snapshots-disks should keep the attached workload name aligned with the Azure disk it is summarizing")
		checkString("os_type", truth.OSType, false, "snapshots-disks OS rendering or Azure-backed validation context", "snapshots-disks should keep OS-type posture aligned with the Azure disk it is summarizing")
		checkString("network_access_policy", truth.NetworkAccessPolicy, false, "snapshots-disks network-access rendering or Azure-backed validation context", "snapshots-disks should keep network access policy aligned with the Azure disk or snapshot it is summarizing")
		checkString("public_network_access", truth.PublicNetworkAccess, false, "snapshots-disks public-network rendering or Azure-backed validation context", "snapshots-disks should keep public network access posture aligned with the Azure disk or snapshot it is summarizing")
		checkString("encryption_type", truth.EncryptionType, false, "snapshots-disks encryption rendering or Azure-backed validation context", "snapshots-disks should keep encryption posture aligned with the Azure disk or snapshot it is summarizing")
		checkResourceID("disk_access_id", truth.DiskAccessID, "snapshots-disks disk-access rendering or Azure-backed validation context", "snapshots-disks should preserve visible disk access resources linked from the Azure asset it is summarizing")
		checkResourceID("disk_encryption_set_id", truth.DiskEncryptionSetID, "snapshots-disks encryption-set rendering or Azure-backed validation context", "snapshots-disks should preserve visible disk encryption set links from the Azure asset it is summarizing")
		checkResourceID("source_resource_id", truth.SourceResourceID, "snapshots-disks source-resource rendering or Azure-backed validation context", "snapshots-disks should preserve the source disk or snapshot ID for visible snapshot rows")
		checkString("source_resource_name", truth.SourceResourceName, false, "snapshots-disks source-resource rendering or Azure-backed validation context", "snapshots-disks should preserve the source disk or snapshot name for visible snapshot rows")
		checkString("source_resource_kind", truth.SourceResourceKind, false, "snapshots-disks source-resource rendering or Azure-backed validation context", "snapshots-disks should preserve whether a snapshot points back to a disk or another snapshot")
		checkBoolPtr("incremental", truth.Incremental, "snapshots-disks snapshot-copy rendering or Azure-backed validation context", "snapshots-disks should preserve whether Azure marks a visible snapshot as incremental")

		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced snapshots-disks id %q with related_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
				"snapshots-disks related-id rendering or Azure-backed validation context",
				"snapshots-disks should preserve the attached workload, source-resource, disk-access, and encryption-set IDs that support the visible asset story",
			))
			break
		}
	}

	return findings
}
