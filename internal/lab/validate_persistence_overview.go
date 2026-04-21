package lab

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

func validatePersistenceOverviewPayload(label string, payload map[string]any, surface SurfaceSnapshot) []Finding {
	findings := []Finding{}
	expectedFields := surface.CommandTopLevelFields["persistence"]
	missingFields := []string{}
	for _, field := range expectedFields {
		if _, ok := payload[field]; !ok {
			missingFields = append(missingFields, field)
		}
	}
	if len(missingFields) > 0 {
		return []Finding{makeBlockingFinding(
			"commands-persistence-overview-missing-fields",
			fmt.Sprintf("%s is missing contracted top-level fields: %s", label, strings.Join(missingFields, ", ")),
			"persistence overview output contract",
			"the grouped helper overview should include every contracted top-level field in JSON mode",
		)}
	}

	groupedCommandName, _ := payload["grouped_command_name"].(string)
	if strings.TrimSpace(groupedCommandName) != "persistence" {
		findings = append(findings, makeBlockingFinding(
			"commands-persistence-overview-group-name-drift",
			fmt.Sprintf("%s reported grouped_command_name %q instead of %q", label, groupedCommandName, "persistence"),
			"persistence overview grouped command identity",
			"the persistence overview helper should identify itself as the persistence grouped command",
		))
	}

	if selectedSurface, ok := payload["selected_surface"]; ok && selectedSurface != nil {
		selectedString, _ := selectedSurface.(string)
		if strings.TrimSpace(selectedString) != "" {
			findings = append(findings, makeBlockingFinding(
				"commands-persistence-overview-selected-surface-drift",
				fmt.Sprintf("%s reported selected_surface %q even though the overview helper should not pin one persistence surface", label, selectedString),
				"persistence overview selection identity",
				"the bare persistence overview should leave selected_surface empty so it reads as a surface index rather than a surface run",
			))
		}
	}

	commandState, _ := payload["command_state"].(string)
	if strings.TrimSpace(commandState) != "implemented" {
		findings = append(findings, makeBlockingFinding(
			"commands-persistence-overview-command-state-drift",
			fmt.Sprintf("%s reported command_state %q instead of %q", label, commandState, "implemented"),
			"persistence overview command-state contract",
			"the persistence overview helper should report the current grouped command state as implemented",
		))
	}

	surfacesPayload, ok := payload["surfaces"].([]any)
	if !ok {
		return append(findings, makeBlockingFinding(
			"commands-persistence-overview-invalid-surfaces",
			label+" did not emit a valid surfaces list",
			"persistence overview surface listing",
			"the persistence overview helper should emit one descriptor per implemented persistence surface",
		))
	}

	expectedSurfaces := groupedOverviewExpectedItems(surface, "persistence")
	actualSurfaces := []string{}

	for _, item := range surfacesPayload {
		surfaceMap, ok := item.(map[string]any)
		if !ok {
			findings = append(findings, makeBlockingFinding(
				"commands-persistence-overview-invalid-surface-entry",
				label+" emitted a surface descriptor that is not a JSON object",
				"persistence overview surface listing",
				"each persistence overview surface descriptor should be an object with the documented fields",
			))
			continue
		}

		requiredSurfaceFields := []string{
			"surface",
			"state",
			"summary",
			"operator_question",
			"backing_commands",
		}
		for _, field := range requiredSurfaceFields {
			if _, ok := surfaceMap[field]; !ok {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("commands-persistence-overview-surface-missing-%s", strings.ReplaceAll(field, "_", "-")),
					fmt.Sprintf("%s emitted a surface descriptor without %s", label, field),
					"persistence overview surface descriptor contract",
					"each persistence overview surface descriptor should include the documented summary, question, and backing-command fields",
				))
			}
		}

		surfaceName, _ := surfaceMap["surface"].(string)
		surfaceState, _ := surfaceMap["state"].(string)
		if strings.TrimSpace(surfaceState) != "implemented" {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("commands-persistence-overview-%s-state-drift", strings.ToLower(strings.TrimSpace(surfaceName))),
				fmt.Sprintf("%s reported persistence surface %q with state %q", label, surfaceName, surfaceState),
				"persistence overview surface state contract",
				"the persistence overview helper should show the current implemented state for shipped persistence surfaces",
			))
		}

		backingCommands, _ := surfaceMap["backing_commands"].([]any)
		if len(backingCommands) == 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("commands-persistence-overview-%s-empty-backing-commands", strings.ToLower(strings.TrimSpace(surfaceName))),
				fmt.Sprintf("%s reported persistence surface %q without backing_commands", label, surfaceName),
				"persistence overview source-command contract",
				"each persistence overview surface descriptor should preserve the minimum backing-command list that anchors the grouped surface",
			))
		}

		if strings.TrimSpace(surfaceName) != "" {
			actualSurfaces = append(actualSurfaces, surfaceName)
		}
	}

	sort.Strings(actualSurfaces)
	if !slices.Equal(actualSurfaces, expectedSurfaces) {
		findings = append(findings, makeBlockingFinding(
			"commands-persistence-overview-surface-set-drift",
			fmt.Sprintf("%s listed persistence surfaces %q, but the current shipped persistence surface set is %q", label, strings.Join(actualSurfaces, ", "), strings.Join(expectedSurfaces, ", ")),
			"persistence overview surface inventory",
			"the persistence overview helper should enumerate the same implemented persistence surface set the current HO-Azure contracts ship",
		))
	}

	return findings
}
