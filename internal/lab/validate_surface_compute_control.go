package lab

import (
	"fmt"
	"slices"
	"strings"
)

func validateComputeControlPayloadAgainstAzureContext(
	entry CommandLogEntry,
	label string,
	payload map[string]any,
	context *liveComputeControlContextArtifact,
) []Finding {
	if entry.SurfaceKind != "families" || entry.SurfaceName != "compute-control" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record the live canary context needed for compute-control validation",
			"lab runner compute-control family context capture",
			"compute-control validation should compare the grouped family rows against the live compute-control canary workload, attached identity, and visible control path",
		)}
	}

	rows := chainPathRows(payload)
	if context.ExpectZeroRows {
		if strings.TrimSpace(context.ZeroRowReason) == "visibility_blocked" {
			findings := []Finding{}
			if len(rows) != 0 {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-family-rows", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced compute-control rows even though the live compute-control context for this viewpoint is currently visibility-blocked", label),
					"compute-control grouped row admission or reduced-view visibility handling",
					"compute-control should not emit defended rows when the live canary path is unreadable from the current viewpoint",
				))
			}
			if len(context.RequiredIssueCollectors) == 0 {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-visibility-boundary-proof", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					label+" passed with a visibility-blocked compute-control context, but the validator does not have the issue collectors needed to prove that boundary explicitly",
					"compute-control live context capture or reduced-view boundary modeling",
					"compute-control should distinguish unreadable paths from genuinely absent defended paths before zero-row results are accepted",
				))
				return findings
			}
			for _, collector := range context.RequiredIssueCollectors {
				if envVarIssue(payload, "collection_error", collector) != nil {
					continue
				}
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-%s-issue", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(collector, "/", "-")),
					fmt.Sprintf("%s did not record the expected collection_error issue for unreadable compute-control collector %q", label, collector),
					"compute-control reduced-view error reporting or live visibility-boundary context",
					"compute-control should keep visibility-blocked zero-row states explicit through collection_error issues instead of letting them read like defended absence",
				))
			}
			return findings
		}
		if len(rows) == 0 {
			return nil
		}
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-unexpected-family-rows", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced compute-control rows even though the live compute-control canary context does not currently expose a defended visible control path for this viewpoint", label),
			"compute-control grouped row admission or reduced-view visibility handling",
			"compute-control should stay empty when the current viewpoint cannot both see the token-capable canary workload and defend the stronger Azure control behind its attached identity",
		)}
	}

	if context.Canary == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-canary", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record the compute-control canary truth needed for validation",
			"compute-control live canary capture",
			"compute-control validation should carry the visible single-identity canary workload and its attached control path forward into the validator",
		)}
	}

	row := findComputeControlRow(payload, context.Canary.AssetID, context.Canary.IdentityID)
	if row == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-%s-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(context.Canary.AssetName))),
			fmt.Sprintf("%s did not surface the expected compute-control row for canary workload %q", label, context.Canary.AssetName),
			"compute-control grouped row admission or canary reuse",
			"compute-control should preserve the defended canary workload row when the live workload, attached identity, and stronger visible Azure control still line up",
		)}
	}

	findings := []Finding{}

	checkString := func(field, expected, likelySeam, expectedOutcome string) {
		actual, _ := row[field].(string)
		if strings.TrimSpace(actual) == strings.TrimSpace(expected) {
			return
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(context.Canary.AssetName)), strings.ReplaceAll(field, "_", "-")),
			fmt.Sprintf("%s surfaced compute-control canary workload %q with %s %q, but the live canary context supports %q", label, context.Canary.AssetName, field, actual, expected),
			likelySeam,
			expectedOutcome,
		))
	}

	checkString("asset_name", context.Canary.AssetName, "compute-control grouped asset naming or canary reuse", "compute-control should keep the canary asset name aligned with the visible workload that is defending the row")
	checkString("asset_kind", context.Canary.AssetKind, "compute-control grouped asset typing or canary reuse", "compute-control should keep the canary asset kind aligned with the visible workload that is defending the row")
	checkString("source_command", "tokens-credentials", "compute-control grouped source-command reuse", "compute-control should keep the canary row anchored to the token-capable workload surface that is driving the grouped path")
	checkString("clue_type", "managed-identity-token", "compute-control grouped clue typing or canary reuse", "compute-control should keep the canary row anchored to the managed-identity token surface it is summarizing")
	checkString("target_service", "azure-control", "compute-control grouped target-service reuse", "compute-control should keep the canary row aimed at the broader Azure control reached by the attached identity")
	checkString("target_resolution", context.Canary.TargetResolution, "compute-control grouped target-resolution reuse", "compute-control should keep the canary row at the defended target-resolution level supported by the current canary identity attachment")

	targetCount, _ := row["target_count"].(float64)
	if int(targetCount) != 1 {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-%s-target-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(context.Canary.AssetName))),
			fmt.Sprintf("%s surfaced compute-control canary workload %q with target_count %d, but the live canary context supports exactly one attached identity lead", label, context.Canary.AssetName, int(targetCount)),
			"compute-control grouped target inventory reuse",
			"compute-control should keep the single-identity canary narrowed to one attached identity target",
		))
	}

	targetIDs := payloadStringSliceValues(row, "target_ids")
	if !slicesContainsNormalized(targetIDs, context.Canary.IdentityID) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-%s-target-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(context.Canary.AssetName))),
			fmt.Sprintf("%s surfaced compute-control canary workload %q without the expected managed identity target id %q", label, context.Canary.AssetName, context.Canary.IdentityID),
			"compute-control grouped identity anchoring or canary reuse",
			"compute-control should keep the canary row anchored to the attached managed identity that currently backs its stronger control path",
		))
	}

	targetNames := payloadStringSliceValues(row, "target_names")
	if !slices.Contains(targetNames, context.Canary.IdentityName) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-%s-target-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(context.Canary.AssetName))),
			fmt.Sprintf("%s surfaced compute-control canary workload %q without the expected managed identity target name %q", label, context.Canary.AssetName, context.Canary.IdentityName),
			"compute-control grouped identity naming or canary reuse",
			"compute-control should keep the canary row anchored to the named attached managed identity that currently backs its stronger control path",
		))
	}

	evidenceCommands := payloadStringSliceValues(row, "evidence_commands")
	for _, expected := range context.Canary.RequiredEvidence {
		if slices.Contains(evidenceCommands, expected) {
			continue
		}
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-%s-evidence-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ToLower(strings.TrimSpace(context.Canary.AssetName))),
			fmt.Sprintf("%s surfaced compute-control canary workload %q without required evidence command %q", label, context.Canary.AssetName, expected),
			"compute-control grouped evidence-command reuse",
			"compute-control should keep the canary row backed by the workload, token, identity, and visible control evidence that currently defends it",
		))
		break
	}

	return findings
}

func findComputeControlRow(payload map[string]any, assetID, identityID string) map[string]any {
	for _, row := range chainPathRows(payload) {
		rowAssetID, _ := row["asset_id"].(string)
		if normalizeResourceID(rowAssetID) != normalizeResourceID(assetID) {
			continue
		}
		rowTargetService, _ := row["target_service"].(string)
		if strings.TrimSpace(rowTargetService) != "azure-control" {
			continue
		}
		targetIDs := payloadStringSliceValues(row, "target_ids")
		if slicesContainsNormalized(targetIDs, identityID) {
			return row
		}
	}
	return nil
}

func chainPathRows(payload map[string]any) []map[string]any {
	rows, _ := payload["paths"].([]any)
	result := []map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, rowMap)
	}
	return result
}
