package lab

import (
	"fmt"
	"slices"
	"strings"
)

func validateNetworkEffectivePayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveNetworkEffectiveContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "network-effective" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-network-effective-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live network-effective context artifact",
			"lab runner network-effective context capture",
			"network-effective validation should compare the tool payload against recorded Azure-backed public-IP and NSG evidence instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["effective_exposures"].([]any)
	if len(rows) != len(context.EffectiveExposures) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d network-effective rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.EffectiveExposures)),
			"network-effective row selection or Azure-backed validation context",
			"network-effective should keep the visible public-IP triage rows aligned with the Azure-backed exposure surfaces the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.EffectiveExposures {
		row := findNetworkEffectiveRow(payload, truth.AssetID, truth.Endpoint)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-row-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the Azure-visible network-effective row for asset %q endpoint %q", label, truth.AssetName, truth.Endpoint),
				"network-effective row selection or Azure-backed validation context",
				"network-effective should keep each Azure-visible public-IP triage row visible for the assets the current viewpoint can enumerate",
			))
			continue
		}

		rowAssetName, _ := row["asset_name"].(string)
		if strings.TrimSpace(rowAssetName) != strings.TrimSpace(truth.AssetName) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with asset_name %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowAssetName, truth.AssetName),
				"network-effective asset naming or Azure-backed validation context",
				"network-effective should keep the asset name aligned with the Azure asset that owns the visible public-IP row",
			))
		}

		rowEndpointType, _ := row["endpoint_type"].(string)
		if strings.TrimSpace(rowEndpointType) != strings.TrimSpace(truth.EndpointType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-endpoint-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with endpoint_type %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowEndpointType, truth.EndpointType),
				"network-effective endpoint typing or Azure-backed validation context",
				"network-effective should preserve whether the triaged surface is an IP or another endpoint type",
			))
		}

		rowExposure, _ := row["effective_exposure"].(string)
		if strings.TrimSpace(rowExposure) != strings.TrimSpace(truth.EffectiveExposure) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-effective-exposure-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with effective_exposure %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowExposure, truth.EffectiveExposure),
				"network-effective exposure classification or Azure-backed validation context",
				"network-effective should keep the exposure priority aligned with the visible Azure NSG evidence for that public-IP path",
			))
		}

		if !slices.Equal(rowStringList(row, "internet_exposed_ports"), truth.InternetExposedPorts) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-internet-ports-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with internet_exposed_ports %v, but Azure-backed expectation is %v", label, truth.Endpoint, rowStringList(row, "internet_exposed_ports"), truth.InternetExposedPorts),
				"network-effective broad internet proof or Azure-backed validation context",
				"network-effective should keep broad internet-facing port evidence aligned with the visible Azure NSG rules for that public-IP path",
			))
		}

		if !slices.Equal(rowStringList(row, "constrained_ports"), truth.ConstrainedPorts) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-constrained-ports-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with constrained_ports %v, but Azure-backed expectation is %v", label, truth.Endpoint, rowStringList(row, "constrained_ports"), truth.ConstrainedPorts),
				"network-effective constrained-port proof or Azure-backed validation context",
				"network-effective should keep narrower allow evidence aligned with the visible Azure NSG rules for that public-IP path",
			))
		}

		if len(truth.ObservedPaths) > 0 && !slices.Equal(rowStringList(row, "observed_paths"), truth.ObservedPaths) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-observed-paths-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with observed_paths %v, but Azure-backed expectation is %v", label, truth.Endpoint, rowStringList(row, "observed_paths"), truth.ObservedPaths),
				"network-effective observed-path rendering or Azure-backed validation context",
				"network-effective should preserve the visible Azure NSG or no-NSG evidence path that explains the current exposure ranking",
			))
		}

		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; !ok {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-related-id-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced endpoint %q with related_ids %v, but Azure-backed expectation includes %q", label, truth.Endpoint, rowStringList(row, "related_ids"), expectedRelatedID),
					"network-effective related-id join or Azure-backed validation context",
					"network-effective should preserve the related Azure resource and identity IDs that support the visible public-IP triage row",
				))
				break
			}
		}

		rowSummary, _ := row["summary"].(string)
		if strings.TrimSpace(truth.SummaryBoundary) != "" && !strings.Contains(strings.ToLower(rowSummary), strings.ToLower(truth.SummaryBoundary)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-summary-boundary-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with summary %q, but the expected evidence boundary phrase %q is missing", label, truth.Endpoint, rowSummary, truth.SummaryBoundary),
				"network-effective summary boundary or Azure-backed validation context",
				"network-effective should keep the evidence-boundary warning aligned with whether Azure surfaced explicit allow proof or only low-confidence visibility clues",
			))
		}
	}

	return findings
}

func validateNetworkPortsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveNetworkPortsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "network-ports" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-network-ports-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live network-ports context artifact",
			"lab runner network-ports context capture",
			"network-ports validation should compare the tool payload against recorded Azure-backed NIC and subnet NSG evidence instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["network_ports"].([]any)
	if len(rows) != len(context.NetworkPorts) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d network-ports rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.NetworkPorts)),
			"network-ports row selection or Azure-backed validation context",
			"network-ports should keep the visible NIC-backed public endpoint rows aligned with the Azure NSG evidence the current viewpoint can actually enumerate",
		))
	}

	for _, truth := range context.NetworkPorts {
		row := findNetworkPortRow(payload, truth.AssetID, truth.Endpoint, truth.Protocol, truth.Port, truth.AllowSourceSummary)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-row-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface the Azure-visible network-ports row for asset %q endpoint %q protocol %q port %q", label, truth.AssetName, truth.Endpoint, truth.Protocol, truth.Port),
				"network-ports row selection or Azure-backed validation context",
				"network-ports should keep each visible NIC-backed ingress row aligned with the Azure NSG evidence the current viewpoint can enumerate",
			))
			continue
		}

		rowAssetName, _ := row["asset_name"].(string)
		if strings.TrimSpace(rowAssetName) != strings.TrimSpace(truth.AssetName) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with asset_name %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowAssetName, truth.AssetName),
				"network-ports asset naming or Azure-backed validation context",
				"network-ports should keep the asset name aligned with the VM that owns the visible public endpoint row",
			))
		}

		rowConfidence, _ := row["exposure_confidence"].(string)
		if strings.TrimSpace(rowConfidence) != strings.TrimSpace(truth.ExposureConfidence) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-confidence-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced endpoint %q with exposure_confidence %q, but Azure-backed expectation is %q", label, truth.Endpoint, rowConfidence, truth.ExposureConfidence),
				"network-ports confidence rendering or Azure-backed validation context",
				"network-ports should keep row confidence aligned with the visible Azure NSG evidence for that viewpoint",
			))
		}

		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; !ok {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-related-id-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced endpoint %q with related_ids %v, but Azure-backed expectation includes %q", label, truth.Endpoint, rowStringList(row, "related_ids"), expectedRelatedID),
					"network-ports related-id join or Azure-backed validation context",
					"network-ports should preserve the VM, NIC, NSG, and identity IDs that support the visible ingress row",
				))
				break
			}
		}
	}

	return findings
}
