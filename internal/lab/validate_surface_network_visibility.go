package lab

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

func rowStringList(row map[string]any, key string) []string {
	values, _ := row[key].([]any)
	items := []string{}
	for _, value := range values {
		item, _ := value.(string)
		if strings.TrimSpace(item) == "" {
			continue
		}
		items = append(items, strings.TrimSpace(item))
	}
	return items
}

func rowIntList(row map[string]any, key string) []int {
	values, _ := row[key].([]any)
	items := []int{}
	for _, value := range values {
		switch typed := value.(type) {
		case float64:
			items = append(items, int(typed))
		case int:
			items = append(items, typed)
		}
	}
	sort.Ints(items)
	return slices.Compact(items)
}

func normalizePlainStringSet(values []string) map[string]struct{} {
	normalized := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		normalized[trimmed] = struct{}{}
	}
	return normalized
}

func normalizeLowerStringSet(values []string) map[string]struct{} {
	normalized := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		normalized[trimmed] = struct{}{}
	}
	return normalized
}

func validateDNSPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveDNSContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "dns" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-dns-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live dns context artifact",
			"lab runner dns context capture",
			"dns validation should compare the tool payload against recorded Azure DNS truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.DNSZones {
		row := findDNSZoneRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-dns-zone-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible DNS zone row for id %q", label, truth.ID),
				"dns asset visibility or Azure-backed validation context",
				"dns should keep visible public and private DNS zones visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowName, _ := row["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced DNS zone id %q as name %q, but Azure reports %q", label, truth.ID, rowName, truth.Name),
				"dns naming or Azure-backed validation context",
				"dns should keep the zone name aligned with the Azure zone it is summarizing",
			))
		}

		rowResourceGroup, _ := row["resource_group"].(string)
		if strings.TrimSpace(truth.ResourceGroup) != "" && strings.TrimSpace(rowResourceGroup) != strings.TrimSpace(truth.ResourceGroup) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-resource-group-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced DNS zone id %q with resource_group %q, but Azure reports %q", label, truth.ID, rowResourceGroup, truth.ResourceGroup),
				"dns resource grouping or Azure-backed validation context",
				"dns should keep resource group placement aligned with the Azure zone it is summarizing",
			))
		}

		rowLocation, _ := row["location"].(string)
		if strings.TrimSpace(truth.Location) != "" && strings.TrimSpace(rowLocation) != strings.TrimSpace(truth.Location) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-location-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced DNS zone id %q with location %q, but Azure reports %q", label, truth.ID, rowLocation, truth.Location),
				"dns location rendering or Azure-backed validation context",
				"dns should keep location aligned with the Azure zone it is summarizing",
			))
		}

		rowZoneKind, _ := row["zone_kind"].(string)
		if strings.TrimSpace(rowZoneKind) != strings.TrimSpace(truth.ZoneKind) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-zone-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced DNS zone id %q with zone_kind %q, but Azure reports %q", label, truth.ID, rowZoneKind, truth.ZoneKind),
				"dns zone-kind rendering or Azure-backed validation context",
				"dns should preserve whether a visible zone is public or private",
			))
		}

		if truth.RecordSetCount != nil {
			rowCount := rowIntPtr(row, "record_set_count")
			if rowCount == nil || *rowCount != *truth.RecordSetCount {
				observed := "<missing>"
				if rowCount != nil {
					observed = fmt.Sprintf("%d", *rowCount)
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-record-set-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced DNS zone id %q with record_set_count %s, but Azure reports %d", label, truth.ID, observed, *truth.RecordSetCount),
					"dns inventory rendering or Azure-backed validation context",
					"dns should keep record-set inventory aligned with the Azure zone it is summarizing",
				))
			}
		}

		if truth.MaxRecordSetCount != nil {
			rowCount := rowIntPtr(row, "max_record_set_count")
			if rowCount == nil || *rowCount != *truth.MaxRecordSetCount {
				observed := "<missing>"
				if rowCount != nil {
					observed = fmt.Sprintf("%d", *rowCount)
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-max-record-set-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced DNS zone id %q with max_record_set_count %s, but Azure reports %d", label, truth.ID, observed, *truth.MaxRecordSetCount),
					"dns inventory rendering or Azure-backed validation context",
					"dns should keep max record-set inventory aligned with the Azure zone it is summarizing",
				))
			}
		}

		expectedNameServers := normalizeLowerStringSet(truth.NameServers)
		observedNameServers := normalizeLowerStringSet(rowStringList(row, "name_servers"))
		if len(expectedNameServers) != len(observedNameServers) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-servers-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced DNS zone id %q with name_servers %v, but Azure reports %v", label, truth.ID, rowStringList(row, "name_servers"), truth.NameServers),
				"dns delegation rendering or Azure-backed validation context",
				"dns should keep visible name servers aligned with Azure for public zones",
			))
		} else {
			for _, expectedNameServer := range truth.NameServers {
				if _, ok := observedNameServers[strings.ToLower(strings.TrimSpace(expectedNameServer))]; !ok {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-name-servers-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced DNS zone id %q with name_servers %v, but Azure reports %v", label, truth.ID, rowStringList(row, "name_servers"), truth.NameServers),
						"dns delegation rendering or Azure-backed validation context",
						"dns should keep visible name servers aligned with Azure for public zones",
					))
					break
				}
			}
		}

		if truth.LinkedVirtualNetworkCount != nil {
			rowCount := rowIntPtr(row, "linked_virtual_network_count")
			if rowCount == nil || *rowCount != *truth.LinkedVirtualNetworkCount {
				observed := "<missing>"
				if rowCount != nil {
					observed = fmt.Sprintf("%d", *rowCount)
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-vnet-link-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced DNS zone id %q with linked_virtual_network_count %s, but Azure reports %d", label, truth.ID, observed, *truth.LinkedVirtualNetworkCount),
					"dns network linkage rendering or Azure-backed validation context",
					"dns should keep private-zone virtual-network link counts aligned with Azure",
				))
			}
		}

		if truth.RegistrationVirtualNetworkCount != nil {
			rowCount := rowIntPtr(row, "registration_virtual_network_count")
			if rowCount == nil || *rowCount != *truth.RegistrationVirtualNetworkCount {
				observed := "<missing>"
				if rowCount != nil {
					observed = fmt.Sprintf("%d", *rowCount)
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-registration-link-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced DNS zone id %q with registration_virtual_network_count %s, but Azure reports %d", label, truth.ID, observed, *truth.RegistrationVirtualNetworkCount),
					"dns network linkage rendering or Azure-backed validation context",
					"dns should keep registration-enabled link counts aligned with Azure",
				))
			}
		}

		if truth.PrivateEndpointReferenceCount != nil {
			rowCount := rowIntPtr(row, "private_endpoint_reference_count")
			if rowCount == nil || *rowCount != *truth.PrivateEndpointReferenceCount {
				observed := "<missing>"
				if rowCount != nil {
					observed = fmt.Sprintf("%d", *rowCount)
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-private-endpoint-ref-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced DNS zone id %q with private_endpoint_reference_count %s, but Azure reports %d", label, truth.ID, observed, *truth.PrivateEndpointReferenceCount),
					"dns private endpoint rendering or Azure-backed validation context",
					"dns should keep private endpoint reference counts aligned with the Azure zone-group truth",
				))
			}
		}

		expectedRelatedIDs := normalizeStringSet(truth.RelatedIDs)
		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		if len(expectedRelatedIDs) != len(observedRelatedIDs) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced DNS zone id %q with related_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
				"dns related-id rendering or Azure-backed validation context",
				"dns should keep zone IDs and private-endpoint references aligned with the Azure relationships it is summarizing",
			))
		} else {
			for _, expectedRelatedID := range truth.RelatedIDs {
				if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; !ok {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-related-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced DNS zone id %q with related_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
						"dns related-id rendering or Azure-backed validation context",
						"dns should keep zone IDs and private-endpoint references aligned with the Azure relationships it is summarizing",
					))
					break
				}
			}
		}
	}
	return findings
}

func validateEndpointsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveEndpointsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "endpoints" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-endpoints-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live endpoints context artifact",
			"lab runner endpoints context capture",
			"endpoints validation should compare the tool payload against recorded Azure endpoint truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["endpoints"].([]any)
	if len(rows) != len(context.Endpoints) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d endpoint rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.Endpoints)),
			"endpoints row selection or Azure-backed validation context",
			"endpoints should keep the visible row count aligned with the Azure-visible workload endpoint surfaces for the current viewpoint",
		))
	}

	for _, truth := range context.Endpoints {
		row := findEndpointRow(payload, truth.SourceAssetID, truth.Endpoint)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-endpoint-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the Azure-visible endpoint %q for asset %q", label, truth.Endpoint, truth.SourceAssetName),
				"endpoints row selection or Azure-backed validation context",
				"endpoints should keep each Azure-visible public IP or managed hostname visible for the assets the current viewpoint can enumerate",
			))
			continue
		}

		rowSourceAssetID, _ := row["source_asset_id"].(string)
		if normalizeResourceID(rowSourceAssetID) != normalizeResourceID(truth.SourceAssetID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-source-asset-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with source_asset_id %q, but Azure reports %q", label, truth.Endpoint, rowSourceAssetID, truth.SourceAssetID),
				"endpoints asset join or Azure-backed validation context",
				"endpoints should preserve the Azure asset ID that produced the visible endpoint row",
			))
		}

		rowAssetName, _ := row["source_asset_name"].(string)
		if strings.TrimSpace(rowAssetName) != strings.TrimSpace(truth.SourceAssetName) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-source-asset-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with source_asset_name %q, but Azure reports %q", label, truth.Endpoint, rowAssetName, truth.SourceAssetName),
				"endpoints asset naming or Azure-backed validation context",
				"endpoints should keep the asset name aligned with the Azure asset that owns the visible endpoint row",
			))
		}

		rowAssetKind, _ := row["source_asset_kind"].(string)
		if normalizeAssetKind(rowAssetKind) != normalizeAssetKind(truth.SourceAssetKind) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-source-asset-kind-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with source_asset_kind %q, but Azure reports %q", label, truth.Endpoint, rowAssetKind, truth.SourceAssetKind),
				"endpoints asset typing or Azure-backed validation context",
				"endpoints should keep the asset kind aligned with the Azure asset that owns the visible endpoint row",
			))
		}

		rowEndpointType, _ := row["endpoint_type"].(string)
		if strings.TrimSpace(rowEndpointType) != strings.TrimSpace(truth.EndpointType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-endpoint-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with endpoint_type %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowEndpointType, truth.EndpointType),
				"endpoints classification or Azure-backed validation context",
				"endpoints should preserve whether each visible surface is an IP or hostname",
			))
		}

		rowExposureFamily, _ := row["exposure_family"].(string)
		if strings.TrimSpace(rowExposureFamily) != strings.TrimSpace(truth.ExposureFamily) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-exposure-family-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with exposure_family %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowExposureFamily, truth.ExposureFamily),
				"endpoints exposure-family classification or Azure-backed validation context",
				"endpoints should keep the exposure family aligned with the Azure-backed surface it is describing",
			))
		}

		rowIngressPath, _ := row["ingress_path"].(string)
		if strings.TrimSpace(rowIngressPath) != strings.TrimSpace(truth.IngressPath) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-ingress-path-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with ingress_path %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowIngressPath, truth.IngressPath),
				"endpoints ingress classification or Azure-backed validation context",
				"endpoints should preserve the ingress path that explains how the visible endpoint is exposed",
			))
		}
	}

	return findings
}
