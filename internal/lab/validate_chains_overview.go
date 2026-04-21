package lab

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

func groupedOverviewExpectedItems(surface SurfaceSnapshot, groupCommand string) []string {
	items := []string{}
	for _, name := range surface.Families {
		if surface.FamilyGroupCommands[name] != groupCommand {
			continue
		}
		items = append(items, name)
	}
	sort.Strings(items)
	return items
}

func validateChainsOverviewPayload(label string, payload map[string]any, surface SurfaceSnapshot) []Finding {
	findings := []Finding{}
	expectedFields := surface.CommandTopLevelFields["chains"]
	missingFields := []string{}
	for _, field := range expectedFields {
		if _, ok := payload[field]; !ok {
			missingFields = append(missingFields, field)
		}
	}
	if len(missingFields) > 0 {
		return []Finding{makeBlockingFinding(
			"commands-chains-overview-missing-fields",
			fmt.Sprintf("%s is missing contracted top-level fields: %s", label, strings.Join(missingFields, ", ")),
			"chains overview output contract",
			"the grouped helper overview should include every contracted top-level field in JSON mode",
		)}
	}

	groupedCommandName, _ := payload["grouped_command_name"].(string)
	if strings.TrimSpace(groupedCommandName) != "chains" {
		findings = append(findings, makeBlockingFinding(
			"commands-chains-overview-group-name-drift",
			fmt.Sprintf("%s reported grouped_command_name %q instead of %q", label, groupedCommandName, "chains"),
			"chains overview grouped command identity",
			"the chains overview helper should identify itself as the chains grouped command",
		))
	}

	if selectedFamily, ok := payload["selected_family"]; ok && selectedFamily != nil {
		selectedString, _ := selectedFamily.(string)
		if strings.TrimSpace(selectedString) != "" {
			findings = append(findings, makeBlockingFinding(
				"commands-chains-overview-selected-family-drift",
				fmt.Sprintf("%s reported selected_family %q even though the overview helper should not pin one family", label, selectedString),
				"chains overview selection identity",
				"the bare chains overview should leave selected_family empty so it reads as a family index rather than a family run",
			))
		}
	}

	familiesPayload, ok := payload["families"].([]any)
	if !ok {
		return append(findings, makeBlockingFinding(
			"commands-chains-overview-invalid-families",
			label+" did not emit a valid families list",
			"chains overview family listing",
			"the chains overview helper should emit one descriptor per implemented grouped family",
		))
	}

	expectedFamilies := groupedOverviewExpectedItems(surface, "chains")
	actualFamilies := []string{}

	for _, item := range familiesPayload {
		familyMap, ok := item.(map[string]any)
		if !ok {
			findings = append(findings, makeBlockingFinding(
				"commands-chains-overview-invalid-family-entry",
				label+" emitted a family descriptor that is not a JSON object",
				"chains overview family listing",
				"each chains overview family descriptor should be an object with the documented fields",
			))
			continue
		}

		requiredFamilyFields := []string{
			"family",
			"state",
			"meaning",
			"summary",
			"allowed_claim",
			"current_gap",
			"best_current_examples",
			"source_commands",
		}
		for _, field := range requiredFamilyFields {
			if _, ok := familyMap[field]; !ok {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("commands-chains-overview-family-missing-%s", strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s emitted a family descriptor without %s", label, field),
					"chains overview family descriptor contract",
					"each chains overview family descriptor should include the documented summary, claim, and source-command fields",
				))
			}
		}

		familyName, _ := familyMap["family"].(string)
		familyState, _ := familyMap["state"].(string)
		if strings.TrimSpace(familyState) != "implemented" {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("commands-chains-overview-%s-state-drift", strings.ToLower(strings.TrimSpace(familyName))),
				fmt.Sprintf("%s reported family %q with state %q", label, familyName, familyState),
				"chains overview family state contract",
				"the chains overview helper should show the current implemented state for shipped grouped families",
			))
		}

		sourceCommands, _ := familyMap["source_commands"].([]any)
		if len(sourceCommands) == 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("commands-chains-overview-%s-empty-sources", strings.ToLower(strings.TrimSpace(familyName))),
				fmt.Sprintf("%s reported family %q without source_commands", label, familyName),
				"chains overview source-command contract",
				"each chains overview family descriptor should preserve the minimum source-command list that anchors the grouped family",
			))
		}

		if strings.TrimSpace(familyName) != "" {
			actualFamilies = append(actualFamilies, familyName)
		}
	}

	sort.Strings(actualFamilies)
	if !slices.Equal(actualFamilies, expectedFamilies) {
		findings = append(findings, makeBlockingFinding(
			"commands-chains-overview-family-set-drift",
			fmt.Sprintf("%s listed families %q, but the current shipped grouped family set is %q", label, strings.Join(actualFamilies, ", "), strings.Join(expectedFamilies, ", ")),
			"chains overview family inventory",
			"the chains overview helper should enumerate the same implemented family set the current HO-Azure contracts ship",
		))
	}

	return findings
}
