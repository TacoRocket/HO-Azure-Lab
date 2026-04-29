package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	ReleasableOutcomes   = []string{"pass", "pass_with_explicit_exceptions"}
	SurfaceStatuses      = []string{"covered", "excepted", "unsupported"}
	ResultStatuses       = []string{"pass", "fail", "blocked", "excepted", "unsupported"}
	BlockingToolSeverity = []string{"blocking", "breaking"}
)

func renderPrompt(finding Finding) string {
	lines := []string{
		"Tool repo blocker from HO-Azure-Lab validation:",
		"- issue: " + finding.Summary,
		"- blocker reason: " + finding.WhyBlocking,
		"- likely seam: " + finding.LikelySeam,
		"- expected outcome: " + finding.ExpectedOutcome,
	}
	return strings.Join(lines, "\n")
}

func validateManifest(manifest Manifest, derived SurfaceSnapshot) ([]string, []string, []string, []string) {
	automaticPasses := []string{}
	automaticFailures := []string{}
	warnings := []string{}

	requiredViewpoints := RequiredViewpoints(manifest)
	if len(requiredViewpoints) == 0 {
		automaticFailures = append(automaticFailures, "manifest does not define any required viewpoints")
	}

	validateSurfaceEntries := func(surfaceKind string, manifestEntries map[string]SurfaceEntry, derivedNames []string) {
		derivedSet := map[string]struct{}{}
		for _, name := range derivedNames {
			derivedSet[name] = struct{}{}
		}
		manifestSet := map[string]struct{}{}
		for name := range manifestEntries {
			manifestSet[name] = struct{}{}
		}

		missing := []string{}
		for _, name := range derivedNames {
			if _, ok := manifestSet[name]; !ok {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			automaticFailures = append(automaticFailures, fmt.Sprintf("manifest is missing %s: %s", surfaceKind, strings.Join(missing, ", ")))
		}

		unexpected := []string{}
		for name := range manifestEntries {
			if _, ok := derivedSet[name]; !ok {
				unexpected = append(unexpected, name)
			}
		}
		sort.Strings(unexpected)
		if len(unexpected) > 0 {
			automaticFailures = append(automaticFailures, fmt.Sprintf("manifest tracks non-shipped %s: %s", surfaceKind, strings.Join(unexpected, ", ")))
		}

		for name, entry := range manifestEntries {
			if !slices.Contains(SurfaceStatuses, entry.Status) {
				automaticFailures = append(automaticFailures, fmt.Sprintf("%s %s has invalid status %q", strings.TrimSuffix(surfaceKind, "s"), name, entry.Status))
			}
			if entry.Status != "covered" && entry.ReasonCode == "" {
				automaticFailures = append(automaticFailures, fmt.Sprintf("%s %s is %s but missing reason_code", strings.TrimSuffix(surfaceKind, "s"), name, entry.Status))
			}
			if entry.ReasonCode == "manual_setup_not_done" && len(entry.ManualSetupSteps) == 0 {
				automaticFailures = append(automaticFailures, fmt.Sprintf("%s %s uses manual_setup_not_done but does not record manual_setup_steps", strings.TrimSuffix(surfaceKind, "s"), name))
			}
			for _, viewpoint := range requiredViewpoints {
				viewpointEntry, ok := entry.Viewpoints[viewpoint]
				if !ok {
					automaticFailures = append(automaticFailures, fmt.Sprintf("%s %s is missing required viewpoint %s", strings.TrimSuffix(surfaceKind, "s"), name, viewpoint))
					continue
				}
				if !slices.Contains(SurfaceStatuses, viewpointEntry.Status) {
					automaticFailures = append(automaticFailures, fmt.Sprintf("%s %s viewpoint %s has invalid status %q", strings.TrimSuffix(surfaceKind, "s"), name, viewpoint, viewpointEntry.Status))
				}
				if viewpointEntry.Status != "covered" && viewpointEntry.ReasonCode == "" {
					automaticFailures = append(automaticFailures, fmt.Sprintf("%s %s viewpoint %s is %s but missing reason_code", strings.TrimSuffix(surfaceKind, "s"), name, viewpoint, viewpointEntry.Status))
				}
			}
		}
	}

	validateSurfaceEntries("commands", manifest.Surfaces.Commands, derived.Commands)
	validateSurfaceEntries("families", manifest.Surfaces.Families, derived.Families)

	if len(automaticFailures) == 0 {
		automaticPasses = append(automaticPasses,
			"manifest accounts for the full shipped command and family surface",
			"manifest records required viewpoints explicitly: "+strings.Join(requiredViewpoints, ", "),
		)
	}
	return automaticPasses, automaticFailures, warnings, requiredViewpoints
}

func expectedScope(manifestEntries map[string]SurfaceEntry) ScopeSummary {
	return buildScopeSummary(manifestEntries)
}

func equalStringSlices(left, right []string) bool {
	leftCopy := append([]string{}, left...)
	rightCopy := append([]string{}, right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func equalStringMapSlices(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValues := range left {
		rightValues, ok := right[key]
		if !ok {
			return false
		}
		if !equalStringSlices(leftValues, rightValues) {
			return false
		}
	}
	return true
}

func payloadGroupedCommandName(payload map[string]any) string {
	value, _ := payload["grouped_command_name"].(string)
	return strings.ToLower(strings.TrimSpace(value))
}

func equalScopeSummary(left, right ScopeSummary) bool {
	return equalStringSlices(left.Covered, right.Covered) &&
		equalStringMapSlices(left.ExceptedByReason, right.ExceptedByReason) &&
		equalStringMapSlices(left.UnsupportedByReason, right.UnsupportedByReason)
}

func checkScopeSection(automaticFailures *[]string, surfaceKind string, manifestEntries map[string]SurfaceEntry, actual ScopeSummary) {
	if !equalScopeSummary(actual, expectedScope(manifestEntries)) {
		*automaticFailures = append(*automaticFailures, fmt.Sprintf("run scope %s does not match the manifest", surfaceKind))
	}
}

func loadRunProfile(runResults RunResult, runResultsPath string) (*RunProfileArtifact, error) {
	record, ok := runResults.Artifacts["run_profile"]
	if !ok {
		return nil, nil
	}
	artifactPath := record.Path
	if !filepath.IsAbs(artifactPath) {
		artifactPath = filepath.Join(filepath.Dir(runResultsPath), artifactPath)
	}
	profile := RunProfileArtifact{}
	if err := LoadJSON(artifactPath, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func runProfileReleaseGate(profile *RunProfileArtifact) bool {
	return profile == nil || (profile.Profile == "release-candidate" && profile.SkippedCount == 0)
}

func runProfileView(profile *RunProfileArtifact) *RunProfileView {
	if profile == nil {
		return nil
	}
	return &RunProfileView{
		Profile:            profile.Profile,
		RequiredViewpoints: append([]string{}, profile.RequiredViewpoints...),
		SelectedViewpoints: append([]string{}, profile.SelectedViewpoints...),
		Selectors: RunProfileSelectors{
			Commands: append([]string{}, profile.Selectors.Commands...),
			Families: append([]string{}, profile.Selectors.Families...),
		},
		SelectedCount: profile.SelectedCount,
		SkippedCount:  profile.SkippedCount,
		ReleaseGate:   runProfileReleaseGate(profile),
	}
}

func runProfileSelectedSet(profile *RunProfileArtifact) map[string]struct{} {
	selected := map[string]struct{}{}
	if profile == nil {
		return selected
	}
	for _, task := range profile.Selected {
		selected[task.SurfaceKind+"\x00"+task.SurfaceName+"\x00"+task.Viewpoint] = struct{}{}
	}
	return selected
}

func runProfileSkippedSet(profile *RunProfileArtifact) map[string]struct{} {
	skipped := map[string]struct{}{}
	if profile == nil {
		return skipped
	}
	for _, task := range profile.Skipped {
		skipped[task.SurfaceKind+"\x00"+task.SurfaceName+"\x00"+task.Viewpoint] = struct{}{}
	}
	return skipped
}

func validateRunResults(manifest Manifest, runResults RunResult, runResultsPath string, manifestCommands, manifestFamilies map[string]SurfaceEntry, requiredViewpoints []string, runProfile *RunProfileArtifact) ([]string, []string, []ReviewTopic, []ToolRepoHandoffPrompt) {
	automaticPasses := []string{}
	automaticFailures := []string{}
	toolRepoHandoffPrompts := []ToolRepoHandoffPrompt{}
	requiredReviewTopics := manifest.Completion.RequiredReviewTopics

	actualRequiredViewpoints := append([]string{}, runResults.Scope.RequiredViewpoints...)
	sort.Strings(actualRequiredViewpoints)
	expectedRequiredViewpoints := append([]string{}, requiredViewpoints...)
	sort.Strings(expectedRequiredViewpoints)
	if !slices.Equal(actualRequiredViewpoints, expectedRequiredViewpoints) {
		automaticFailures = append(automaticFailures, "run scope required viewpoints do not match the manifest")
	}
	checkScopeSection(&automaticFailures, "commands", manifestCommands, runResults.Scope.Commands)
	checkScopeSection(&automaticFailures, "families", manifestFamilies, runResults.Scope.Families)

	selectedSet := runProfileSelectedSet(runProfile)
	skippedSet := runProfileSkippedSet(runProfile)
	checkSurfaceResults := func(surfaceKind string, manifestEntries map[string]SurfaceEntry, runSurfaceResults map[string]map[string]ViewpointResult) {
		for name, entry := range manifestEntries {
			for viewpoint, viewpointEntry := range entry.Viewpoints {
				if viewpointEntry.Status != "covered" {
					continue
				}
				taskKey := surfaceKind + "\x00" + name + "\x00" + viewpoint
				if runProfile != nil {
					if _, ok := skippedSet[taskKey]; ok {
						continue
					}
					if _, ok := selectedSet[taskKey]; !ok {
						automaticFailures = append(automaticFailures, fmt.Sprintf("run profile does not classify %s %s viewpoint %s as selected or skipped", strings.TrimSuffix(surfaceKind, "s"), name, viewpoint))
						continue
					}
				}
				resultRecord, ok := runSurfaceResults[name][viewpoint]
				if !ok {
					automaticFailures = append(automaticFailures, fmt.Sprintf("run results are missing %s %s viewpoint %s", strings.TrimSuffix(surfaceKind, "s"), name, viewpoint))
					continue
				}
				if !slices.Contains(ResultStatuses, resultRecord.Status) {
					automaticFailures = append(automaticFailures, fmt.Sprintf("run results use invalid status %q for %s %s viewpoint %s", resultRecord.Status, strings.TrimSuffix(surfaceKind, "s"), name, viewpoint))
					continue
				}
				if resultRecord.Status != "pass" {
					automaticFailures = append(automaticFailures, fmt.Sprintf("%s %s viewpoint %s did not pass (status=%s)", strings.TrimSuffix(surfaceKind, "s"), name, viewpoint, resultRecord.Status))
				}
			}
		}
	}

	checkSurfaceResults("commands", manifestCommands, runResults.SurfaceResults.Commands)
	checkSurfaceResults("families", manifestFamilies, runResults.SurfaceResults.Families)

	startedAt, err := time.Parse(time.RFC3339, runResults.StartedAt)
	if err != nil {
		automaticFailures = append(automaticFailures, "run results started_at is not valid RFC3339")
	}
	runBaseDir := filepath.Dir(runResultsPath)
	for _, artifact := range manifest.Completion.RequiredArtifacts {
		if artifact.RequiredWhen == "demo_capture_expected" && !runResults.DemoCaptureExpected {
			continue
		}
		artifactRecord, ok := runResults.Artifacts[artifact.ID]
		if !ok {
			automaticFailures = append(automaticFailures, "required artifact record is missing for "+artifact.ID)
			continue
		}
		artifactPath := artifactRecord.Path
		if !filepath.IsAbs(artifactPath) {
			artifactPath = filepath.Join(runBaseDir, artifactPath)
		}
		info, err := os.Stat(artifactPath)
		if err != nil {
			automaticFailures = append(automaticFailures, fmt.Sprintf("required artifact file is missing for %s: %s", artifact.ID, artifactPath))
			continue
		}
		if !startedAt.IsZero() && info.ModTime().UTC().Before(startedAt.UTC()) {
			automaticFailures = append(automaticFailures, fmt.Sprintf("artifact %s looks stale because it predates the run start", artifact.ID))
		}
	}

	if manifest.Completion.RequireFinalOutcome && runResults.FinalOutcome == "" {
		automaticFailures = append(automaticFailures, "run results are missing final_outcome")
	}
	if manifest.Completion.RequireFindings && runResults.Findings == nil {
		automaticFailures = append(automaticFailures, "run results are missing findings")
	}
	if manifest.Completion.RequireTeardown && runResults.Teardown.Status == "" {
		automaticFailures = append(automaticFailures, "run results are missing teardown or standing-resource verification")
	}
	if manifest.Completion.RequireTeardown && runResults.Teardown.Status != "verified" && runResults.Teardown.Status != "standing-resource-recorded" {
		automaticFailures = append(automaticFailures, "teardown status must be verified or standing-resource-recorded")
	}

	for _, finding := range runResults.Findings {
		if finding.Owner != "tool_repo" || !slices.Contains(BlockingToolSeverity, finding.Severity) {
			continue
		}
		missingFields := []string{}
		if finding.WhyBlocking == "" {
			missingFields = append(missingFields, "why_blocking")
		}
		if finding.LikelySeam == "" {
			missingFields = append(missingFields, "likely_seam")
		}
		if finding.ExpectedOutcome == "" {
			missingFields = append(missingFields, "expected_outcome")
		}
		if len(missingFields) > 0 {
			automaticFailures = append(automaticFailures, fmt.Sprintf("tool-repo blocker %s is missing fields: %s", finding.ID, strings.Join(missingFields, ", ")))
			continue
		}
		toolRepoHandoffPrompts = append(toolRepoHandoffPrompts, ToolRepoHandoffPrompt{
			FindingID: finding.ID,
			Prompt:    renderPrompt(finding),
		})
	}

	if len(automaticFailures) == 0 {
		if runProfile != nil {
			automaticPasses = append(automaticPasses, fmt.Sprintf("run profile %s completed selected scope (%d selected, %d skipped)", runProfile.Profile, runProfile.SelectedCount, runProfile.SkippedCount))
		}
		automaticPasses = append(automaticPasses,
			"completion-verifier checks passed for required covered surfaces",
			"required artifacts and teardown records are present and fresh",
		)
	}
	return automaticPasses, automaticFailures, requiredReviewTopics, toolRepoHandoffPrompts
}

func ValidateLab(manifestPath, hoAzureDir, runResultsPath string) (ValidationSummary, error) {
	var manifest Manifest
	if err := LoadJSON(manifestPath, &manifest); err != nil {
		return ValidationSummary{}, err
	}
	derivedSurface, err := DeriveSurface(hoAzureDir)
	if err != nil {
		return ValidationSummary{}, err
	}

	automaticPasses, automaticFailures, warnings, requiredViewpoints := validateManifest(manifest, derivedSurface)
	requiredReviewTopics := manifest.Completion.RequiredReviewTopics
	toolRepoHandoffPrompts := []ToolRepoHandoffPrompt{}
	var runResults *RunResult
	var runProfile *RunProfileArtifact

	if runResultsPath != "" {
		loaded := RunResult{}
		if err := LoadJSON(runResultsPath, &loaded); err != nil {
			return ValidationSummary{}, err
		}
		runResults = &loaded
		loadedRunProfile, err := loadRunProfile(loaded, runResultsPath)
		if err != nil {
			return ValidationSummary{}, err
		}
		runProfile = loadedRunProfile
		runPasses, runFailures, runReviewTopics, runHandoffs := validateRunResults(
			manifest,
			loaded,
			runResultsPath,
			manifest.Surfaces.Commands,
			manifest.Surfaces.Families,
			requiredViewpoints,
			runProfile,
		)
		automaticPasses = append(automaticPasses, runPasses...)
		automaticFailures = append(automaticFailures, runFailures...)
		requiredReviewTopics = runReviewTopics
		toolRepoHandoffPrompts = runHandoffs
	}

	completionStatus := "complete"
	if len(automaticFailures) > 0 {
		completionStatus = "incomplete"
	}
	releaseReady := false
	if completionStatus == "complete" && runResults != nil && slices.Contains(ReleasableOutcomes, runResults.FinalOutcome) && runProfileReleaseGate(runProfile) {
		releaseReady = true
	}

	return ValidationSummary{
		CompletionStatus:       completionStatus,
		ReleaseReady:           releaseReady,
		AutomaticPasses:        automaticPasses,
		AutomaticFailures:      automaticFailures,
		RequiredReviewTopics:   requiredReviewTopics,
		ToolRepoHandoffPrompts: toolRepoHandoffPrompts,
		Summary: ValidationSummaryEnvelope{
			RequiredViewpoints:  requiredViewpoints,
			ShippedCommandCount: len(derivedSurface.Commands),
			ShippedFamilyCount:  len(derivedSurface.Families),
			RunProfile:          runProfileView(runProfile),
			Commands:            summarizeSurfaceEntries(manifest.Surfaces.Commands),
			Families:            summarizeSurfaceEntries(manifest.Surfaces.Families),
		},
		Warnings: warnings,
	}, nil
}

func RenderText(payload ValidationSummary) string {
	lines := []string{
		"Completion: " + payload.CompletionStatus,
		fmt.Sprintf("Release ready: %s", map[bool]string{true: "yes", false: "no"}[payload.ReleaseReady]),
		fmt.Sprintf("Shipped surface: %d commands, %d families", payload.Summary.ShippedCommandCount, payload.Summary.ShippedFamilyCount),
		"Required viewpoints: " + strings.Join(payload.Summary.RequiredViewpoints, ", "),
		fmt.Sprintf("Manifest command split: %d covered, %d excepted, %d unsupported", payload.Summary.Commands.Counts["covered"], payload.Summary.Commands.Counts["excepted"], payload.Summary.Commands.Counts["unsupported"]),
		fmt.Sprintf("Manifest family split: %d covered, %d excepted, %d unsupported", payload.Summary.Families.Counts["covered"], payload.Summary.Families.Counts["excepted"], payload.Summary.Families.Counts["unsupported"]),
	}
	if payload.Summary.RunProfile != nil {
		lines = append(lines, fmt.Sprintf("Run profile: %s (%d selected, %d skipped, release gate: %s)", payload.Summary.RunProfile.Profile, payload.Summary.RunProfile.SelectedCount, payload.Summary.RunProfile.SkippedCount, map[bool]string{true: "yes", false: "no"}[payload.Summary.RunProfile.ReleaseGate]))
		if len(payload.Summary.RunProfile.SelectedViewpoints) > 0 {
			lines = append(lines, "Selected viewpoints: "+strings.Join(payload.Summary.RunProfile.SelectedViewpoints, ", "))
		}
	}

	if manual := payload.Summary.Commands.ByReason["manual_setup_not_done"]; len(manual) > 0 {
		lines = append(lines, "Manual-setup command seams: "+strings.Join(manual, ", "))
	}

	followup := append([]string{}, payload.Summary.Commands.ByReason["first_gate_followup"]...)
	followup = append(followup, payload.Summary.Families.ByReason["first_gate_followup"]...)
	if len(followup) > 0 {
		lines = append(lines, "Tracked first-gate follow-up surfaces: "+strings.Join(followup, ", "))
	}

	if len(payload.AutomaticPasses) > 0 {
		lines = append(lines, "", "Automatic passes:")
		for _, item := range payload.AutomaticPasses {
			lines = append(lines, "- "+item)
		}
	}
	if len(payload.AutomaticFailures) > 0 {
		lines = append(lines, "", "Automatic failures:")
		for _, item := range payload.AutomaticFailures {
			lines = append(lines, "- "+item)
		}
	}
	if len(payload.RequiredReviewTopics) > 0 {
		lines = append(lines, "", "Required review topics:")
		for _, topic := range payload.RequiredReviewTopics {
			lines = append(lines, "- "+topic.Prompt)
		}
	}
	if len(payload.ToolRepoHandoffPrompts) > 0 {
		lines = append(lines, "", "Tool-repo handoff prompts:")
		for _, prompt := range payload.ToolRepoHandoffPrompts {
			lines = append(lines, "- finding: "+prompt.FindingID)
			for _, promptLine := range strings.Split(prompt.Prompt, "\n") {
				lines = append(lines, "  "+promptLine)
			}
		}
	}
	if len(payload.Warnings) > 0 {
		lines = append(lines, "", "Warnings:")
		for _, item := range payload.Warnings {
			lines = append(lines, "- "+item)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func groupedSelectionKey(groupCommand string) string {
	switch groupCommand {
	case "chains":
		return "selected_family"
	case "persistence":
		return "selected_surface"
	default:
		return ""
	}
}

func groupedFamilyIdentityKey(groupCommand string) string {
	switch groupCommand {
	case "chains":
		return "family"
	case "persistence":
		return "surface"
	default:
		return ""
	}
}

func groupedFamilyTopLevelFields(groupCommand string) []string {
	switch groupCommand {
	case "chains":
		return []string{
			"metadata",
			"grouped_command_name",
			"family",
			"input_mode",
			"command_state",
			"summary",
			"claim_boundary",
			"artifact_preference_order",
			"backing_commands",
			"source_artifacts",
			"paths",
			"issues",
		}
	case "persistence":
		return []string{
			"metadata",
			"grouped_command_name",
			"surface",
			"input_mode",
			"command_state",
			"summary",
			"backing_commands",
			"issues",
		}
	default:
		return nil
	}
}

func makeBlockingFinding(findingID, summary, likelySeam, expectedOutcome string) Finding {
	return Finding{
		ID:              findingID,
		Owner:           "tool_repo",
		Severity:        "blocking",
		Summary:         summary,
		WhyBlocking:     "the live payload does not satisfy the current shipped output contract",
		LikelySeam:      likelySeam,
		ExpectedOutcome: expectedOutcome,
	}
}

func validateWhoAmIPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAzureContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "whoami" {
		return nil
	}

	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-azure-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live Azure context artifact",
			"lab runner Azure context capture",
			"whoami validation should compare the tool payload against recorded live Azure context instead of lab-config fallback",
		)}
	}

	findings := []Finding{}
	if tenantID, _ := payload["tenant_id"].(string); tenantID != context.TenantID {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-tenant-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported tenant_id %q, but Azure returned %q for the current validation context", label, tenantID, context.TenantID),
			"whoami tenant context or Azure-backed validation context",
			"whoami should report the tenant_id from the live Azure validation context",
		))
	}

	metadata, _ := payload["metadata"].(map[string]any)
	if metadataSubscription, _ := metadata["subscription_id"].(string); metadataSubscription != context.SubscriptionID {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-metadata-subscription-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported metadata.subscription_id %q, but Azure returned %q for the current validation context", label, metadataSubscription, context.SubscriptionID),
			"whoami metadata rendering or Azure-backed validation context",
			"whoami metadata should report the subscription_id from the live Azure validation context",
		))
	}
	if metadataTenant, _ := metadata["tenant_id"].(string); metadataTenant != context.TenantID {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-metadata-tenant-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported metadata.tenant_id %q, but Azure returned %q for the current validation context", label, metadataTenant, context.TenantID),
			"whoami metadata rendering or Azure-backed validation context",
			"whoami metadata should report the tenant_id from the live Azure validation context",
		))
	}

	subscription, _ := payload["subscription"].(map[string]any)
	if subscriptionID, _ := subscription["id"].(string); subscriptionID != context.SubscriptionID {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-subscription-id-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported subscription.id %q, but Azure returned %q for the current validation context", label, subscriptionID, context.SubscriptionID),
			"whoami subscription rendering or Azure-backed validation context",
			"whoami should report the subscription_id from the live Azure validation context",
		))
	}

	principal, _ := payload["principal"].(map[string]any)
	if principalType, _ := principal["principal_type"].(string); normalizePrincipalType(principalType) != normalizePrincipalType(context.PrincipalType) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-principal-type-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported principal.principal_type %q, but Azure returned %q for the current validation context", label, principalType, context.PrincipalType),
			"whoami principal classification or Azure-backed validation context",
			"whoami should classify the current Azure-backed principal type truthfully",
		))
	}
	if principalID, _ := principal["id"].(string); principalID != context.PrincipalID {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-principal-id-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported principal.id %q, but Azure returned %q for the current validation context", label, principalID, context.PrincipalID),
			"whoami principal identification or Azure-backed validation context",
			"whoami should identify the currently authenticated Azure principal truthfully",
		))
	}
	if context.PrincipalName != "" {
		if displayName, _ := principal["display_name"].(string); displayName != context.PrincipalName {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-name-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s reported principal.display_name %q, but Azure returned %q for the current validation context", label, displayName, context.PrincipalName),
				"whoami principal rendering or Azure-backed validation context",
				"whoami should report the current Azure principal display name truthfully when Azure exposes it",
			))
		}
	}

	return findings
}

func normalizePrincipalType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	normalized = replacer.Replace(normalized)
	switch normalized {
	case "managedidentity":
		return "serviceprincipal"
	default:
		return normalized
	}
}

func normalizeResourceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeIdentityType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	return replacer.Replace(normalized)
}

func normalizeAssetKind(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	return replacer.Replace(normalized)
}

func normalizeStringSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		normalized := normalizeResourceID(value)
		if normalized == "" {
			continue
		}
		result[normalized] = struct{}{}
	}
	return result
}

func findManagedIdentityRowsByPrincipalID(payload map[string]any, principalID string) []map[string]any {
	rows, _ := payload["identities"].([]any)
	matches := []map[string]any{}
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowPrincipalID, _ := rowMap["principal_id"].(string)
		if rowPrincipalID == principalID {
			matches = append(matches, rowMap)
		}
	}
	return matches
}

func managedIdentityRowHasAttachment(row map[string]any, attachedResourceID string) bool {
	attachedRows, _ := row["attached_to"].([]any)
	expected := normalizeResourceID(attachedResourceID)
	for _, attached := range attachedRows {
		attachedID, _ := attached.(string)
		if normalizeResourceID(attachedID) == expected {
			return true
		}
	}
	return false
}

func managedIdentityRowTypeMatches(row map[string]any, expectedType string) bool {
	rowType, _ := row["identity_type"].(string)
	return normalizeIdentityType(rowType) == normalizeIdentityType(expectedType)
}

func collectManagedIdentityAttachments(rows []map[string]any) map[string]struct{} {
	collected := map[string]struct{}{}
	for _, row := range rows {
		attachedRows, _ := row["attached_to"].([]any)
		for _, attached := range attachedRows {
			attachedID, _ := attached.(string)
			if normalizeResourceID(attachedID) == "" {
				continue
			}
			collected[normalizeResourceID(attachedID)] = struct{}{}
		}
	}
	return collected
}

func validateManagedIdentitiesPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveManagedIdentitiesContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "managed-identities" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-managed-identities-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live managed identities context artifact",
			"lab runner managed identities context capture",
			"managed-identities validation should compare the tool payload against recorded Azure attachment truth for visible managed identity principals",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.Identities {
		rows := findManagedIdentityRowsByPrincipalID(payload, truth.PrincipalID)
		if len(rows) == 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-%s-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, truth.PrincipalID),
				fmt.Sprintf("%s did not surface a managed identity row for Azure principal_id %q", label, truth.PrincipalID),
				"managed-identities identity visibility or Azure-backed validation context",
				"managed-identities should keep visible workload-attached managed identity principals visible when Azure still exposes them",
			))
			continue
		}
		typeMatched := false
		for _, row := range rows {
			if managedIdentityRowTypeMatches(row, truth.IdentityType) {
				typeMatched = true
				break
			}
		}
		if !typeMatched {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-%s-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, truth.PrincipalID),
				fmt.Sprintf("%s surfaced Azure principal_id %q, but did not keep its managed identity type aligned with Azure", label, truth.PrincipalID),
				"managed-identities identity typing or Azure-backed validation context",
				"managed-identities should classify visible managed identity principals consistently with Azure attachment truth",
			))
		}
		observedAttachments := collectManagedIdentityAttachments(rows)
		missingAttachments := []string{}
		for _, expectedAttachment := range truth.AttachedTo {
			if _, ok := observedAttachments[normalizeResourceID(expectedAttachment)]; !ok {
				missingAttachments = append(missingAttachments, expectedAttachment)
			}
		}
		if len(missingAttachments) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-%s-attachment-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, truth.PrincipalID),
				fmt.Sprintf("%s lost Azure-backed workload attachments for principal_id %q: %s", label, truth.PrincipalID, strings.Join(missingAttachments, ", ")),
				"managed-identities attachment rendering or Azure-backed validation context",
				"managed-identities should preserve the workload attachments Azure currently shows for visible managed identity principals",
			))
		}
	}
	return findings
}

func findWorkloadRowByAssetID(payload map[string]any, assetID string) map[string]any {
	rows, _ := payload["workloads"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		if normalizeResourceID(rowAssetID) == normalizeResourceID(assetID) {
			return rowMap
		}
	}
	return nil
}

func workloadRowIdentityIDs(row map[string]any) []string {
	values, _ := row["identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func workloadRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["identity_type"].(string)
	rowPrincipalID, _ := row["identity_principal_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		len(workloadRowIdentityIDs(row)) > 0
}

func validateWorkloadsPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveWorkloadsContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "workloads" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-workloads-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live workloads context artifact",
			"lab runner workloads context capture",
			"workloads validation should compare the tool payload against recorded Azure workload truth instead of remembered row examples",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.Workloads {
		row := findWorkloadRowByAssetID(payload, truth.AssetID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-%s-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, normalizeAssetKind(truth.AssetKind)),
				fmt.Sprintf("%s did not surface an Azure-visible workload row for asset_id %q", label, truth.AssetID),
				"workloads asset visibility or Azure-backed validation context",
				"workloads should keep visible Azure workload assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowAssetKind, _ := row["asset_kind"].(string)
		if normalizeAssetKind(rowAssetKind) != normalizeAssetKind(truth.AssetKind) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-asset-kind-drift-%s", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, normalizeAssetKind(truth.AssetKind)),
				fmt.Sprintf("%s surfaced asset_id %q as asset_kind %q, but Azure workload truth maps it to %q", label, truth.AssetID, rowAssetKind, truth.AssetKind),
				"workloads asset typing or Azure-backed validation context",
				"workloads should keep the workload kind aligned with the Azure workload type it is summarizing",
			))
		}

		if normalizeIdentityType(truth.IdentityType) == "" && len(truth.IdentityIDs) == 0 {
			if workloadRowHasIdentityContext(row) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-identity-context-%s", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, normalizeAssetKind(truth.AssetKind)),
					fmt.Sprintf("%s surfaced workload asset_id %q with managed identity context, but Azure does not currently show identity on that workload", label, truth.AssetID),
					"workloads identity rendering or Azure-backed validation context",
					"workloads should not describe a workload as identity-bearing when Azure shows that workload has no managed identity configured",
				))
			}
			continue
		}
		if !workloadRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing-%s", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, normalizeAssetKind(truth.AssetKind)),
				fmt.Sprintf("%s surfaced workload asset_id %q, but lost the Azure-visible identity context for that workload", label, truth.AssetID),
				"workloads identity rendering or Azure-backed validation context",
				"workloads should preserve identity-bearing workload context when Azure shows that workload carrying managed identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["identity_type"].(string)
		if normalizeIdentityType(truth.IdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.IdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift-%s", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, normalizeAssetKind(truth.AssetKind)),
				fmt.Sprintf("%s surfaced workload asset_id %q with identity_type %q, but Azure workload truth reports %q", label, truth.AssetID, rowIdentityType, truth.IdentityType),
				"workloads identity typing or Azure-backed validation context",
				"workloads should keep workload identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		if len(expectedIdentityIDs) == 0 {
			continue
		}
		observedIdentityIDs := normalizeStringSet(workloadRowIdentityIDs(row))
		missingIdentityIDs := []string{}
		for _, expectedIdentityID := range truth.IdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
				missingIdentityIDs = append(missingIdentityIDs, expectedIdentityID)
			}
		}
		if len(missingIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift-%s", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, normalizeAssetKind(truth.AssetKind)),
				fmt.Sprintf("%s lost Azure-visible workload identity IDs for asset_id %q: %s", label, truth.AssetID, strings.Join(missingIdentityIDs, ", ")),
				"workloads user-assigned identity rendering or Azure-backed validation context",
				"workloads should preserve the user-assigned identity IDs Azure currently shows on visible workload assets",
			))
		}
	}
	return findings
}

func findAppServiceRowByID(payload map[string]any, appID string) map[string]any {
	rows, _ := payload["app_services"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(appID) {
			return rowMap
		}
	}
	return nil
}

func appServiceRowIdentityIDs(row map[string]any) []string {
	values, _ := row["workload_identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func appServiceRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["workload_identity_type"].(string)
	rowPrincipalID, _ := row["workload_principal_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		len(appServiceRowIdentityIDs(row)) > 0
}

func validateAppServicesPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAppServicesContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "app-services" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-app-services-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live app services context artifact",
			"lab runner app services context capture",
			"app-services validation should compare the tool payload against recorded Azure App Service truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.AppServices {
		row := findAppServiceRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-app-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible App Service row for id %q", label, truth.ID),
				"app-services asset visibility or Azure-backed validation context",
				"app-services should keep visible Azure App Service assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowName, _ := row["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced App Service id %q as name %q, but Azure reports %q", label, truth.ID, rowName, truth.Name),
				"app-services naming or Azure-backed validation context",
				"app-services should keep the App Service name aligned with the Azure asset it is summarizing",
			))
		}

		rowHostname, _ := row["default_hostname"].(string)
		if strings.TrimSpace(truth.Hostname) != "" && strings.TrimSpace(rowHostname) != strings.TrimSpace(truth.Hostname) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-hostname-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced App Service id %q with hostname %q, but Azure reports %q", label, truth.ID, rowHostname, truth.Hostname),
				"app-services hostname rendering or Azure-backed validation context",
				"app-services should keep the visible default hostname aligned with the Azure App Service truth",
			))
		}

		rowPublicNetworkAccess, _ := row["public_network_access"].(string)
		if strings.TrimSpace(truth.PublicNetworkAccess) != "" && !strings.EqualFold(strings.TrimSpace(rowPublicNetworkAccess), strings.TrimSpace(truth.PublicNetworkAccess)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-public-network-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced App Service id %q with public_network_access %q, but Azure reports %q", label, truth.ID, rowPublicNetworkAccess, truth.PublicNetworkAccess),
				"app-services public network posture or Azure-backed validation context",
				"app-services should keep the public network posture aligned with the Azure App Service it is summarizing",
			))
		}

		if normalizeIdentityType(truth.IdentityType) == "" && len(truth.IdentityIDs) == 0 {
			continue
		}
		if !appServiceRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced App Service id %q, but lost the Azure-visible identity context for that app", label, truth.ID),
				"app-services identity rendering or Azure-backed validation context",
				"app-services should preserve managed identity context when Azure shows that App Service carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["workload_identity_type"].(string)
		if normalizeIdentityType(truth.IdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.IdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced App Service id %q with workload_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.IdentityType),
				"app-services identity typing or Azure-backed validation context",
				"app-services should keep App Service identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		if len(expectedIdentityIDs) == 0 {
			continue
		}
		observedIdentityIDs := normalizeStringSet(appServiceRowIdentityIDs(row))
		missingIdentityIDs := []string{}
		for _, expectedIdentityID := range truth.IdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
				missingIdentityIDs = append(missingIdentityIDs, expectedIdentityID)
			}
		}
		if len(missingIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s lost Azure-visible App Service identity IDs for id %q: %s", label, truth.ID, strings.Join(missingIdentityIDs, ", ")),
				"app-services user-assigned identity rendering or Azure-backed validation context",
				"app-services should preserve the user-assigned identity IDs Azure currently shows on visible App Service assets",
			))
		}
	}
	return findings
}

func findContainerInstanceRowByID(payload map[string]any, containerInstanceID string) map[string]any {
	rows, _ := payload["container_instances"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(containerInstanceID) {
			return rowMap
		}
	}
	return nil
}

func containerInstanceRowIdentityIDs(row map[string]any) []string {
	values, _ := row["workload_identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func containerInstanceRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["workload_identity_type"].(string)
	rowPrincipalID, _ := row["workload_principal_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		len(containerInstanceRowIdentityIDs(row)) > 0
}

func findACRRowByID(payload map[string]any, registryID string) map[string]any {
	rows, _ := payload["registries"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(registryID) {
			return rowMap
		}
	}
	return nil
}

func findApplicationGatewayRowByID(payload map[string]any, gatewayID string) map[string]any {
	rows, _ := payload["application_gateways"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(gatewayID) {
			return rowMap
		}
	}
	return nil
}

func findAPIMgmtRowByID(payload map[string]any, serviceID string) map[string]any {
	rows, _ := payload["api_management_services"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(serviceID) {
			return rowMap
		}
	}
	return nil
}

func findDatabaseServerRowByID(payload map[string]any, serverID string) map[string]any {
	rows, _ := payload["database_servers"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(serverID) {
			return rowMap
		}
	}
	return nil
}

func acrRowIdentityIDs(row map[string]any) []string {
	values, _ := row["workload_identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func acrRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["workload_identity_type"].(string)
	rowPrincipalID, _ := row["workload_principal_id"].(string)
	rowClientID, _ := row["workload_client_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		strings.TrimSpace(rowClientID) != "" ||
		len(acrRowIdentityIDs(row)) > 0
}

func findAKSRowByID(payload map[string]any, clusterID string) map[string]any {
	rows, _ := payload["aks_clusters"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(clusterID) {
			return rowMap
		}
	}
	return nil
}

func findDNSZoneRowByID(payload map[string]any, zoneID string) map[string]any {
	rows, _ := payload["dns_zones"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowID, _ := rowMap["id"].(string)
		if normalizeResourceID(rowID) == normalizeResourceID(zoneID) {
			return rowMap
		}
	}
	return nil
}

func findEndpointRow(payload map[string]any, sourceAssetID, endpoint string) map[string]any {
	rows, _ := payload["endpoints"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowSourceAssetID, _ := rowMap["source_asset_id"].(string)
		rowEndpoint, _ := rowMap["endpoint"].(string)
		if normalizeResourceID(rowSourceAssetID) == normalizeResourceID(sourceAssetID) &&
			strings.TrimSpace(rowEndpoint) == strings.TrimSpace(endpoint) {
			return rowMap
		}
	}
	return nil
}

func findNetworkEffectiveRow(payload map[string]any, assetID, endpoint string) map[string]any {
	rows, _ := payload["effective_exposures"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		rowEndpoint, _ := rowMap["endpoint"].(string)
		if normalizeResourceID(rowAssetID) == normalizeResourceID(assetID) &&
			strings.TrimSpace(rowEndpoint) == strings.TrimSpace(endpoint) {
			return rowMap
		}
	}
	return nil
}

func findNetworkPortRow(payload map[string]any, assetID, endpoint, protocol, port, allowSourceSummary string) map[string]any {
	rows, _ := payload["network_ports"].([]any)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowAssetID, _ := rowMap["asset_id"].(string)
		rowEndpoint, _ := rowMap["endpoint"].(string)
		rowProtocol, _ := rowMap["protocol"].(string)
		rowPort, _ := rowMap["port"].(string)
		rowAllowSourceSummary, _ := rowMap["allow_source_summary"].(string)
		if normalizeResourceID(rowAssetID) == normalizeResourceID(assetID) &&
			strings.TrimSpace(rowEndpoint) == strings.TrimSpace(endpoint) &&
			strings.TrimSpace(rowProtocol) == strings.TrimSpace(protocol) &&
			strings.TrimSpace(rowPort) == strings.TrimSpace(port) &&
			strings.TrimSpace(rowAllowSourceSummary) == strings.TrimSpace(allowSourceSummary) {
			return rowMap
		}
	}
	return nil
}

func aksRowIdentityIDs(row map[string]any) []string {
	values, _ := row["cluster_identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func aksRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["cluster_identity_type"].(string)
	rowPrincipalID, _ := row["cluster_principal_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		len(aksRowIdentityIDs(row)) > 0
}

func databaseRowIdentityIDs(row map[string]any) []string {
	values, _ := row["workload_identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func databaseRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["workload_identity_type"].(string)
	rowPrincipalID, _ := row["workload_principal_id"].(string)
	rowClientID, _ := row["workload_client_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		strings.TrimSpace(rowClientID) != "" ||
		len(databaseRowIdentityIDs(row)) > 0
}

func apiMgmtRowIdentityIDs(row map[string]any) []string {
	values, _ := row["workload_identity_ids"].([]any)
	identityIDs := []string{}
	for _, value := range values {
		identityID, _ := value.(string)
		if strings.TrimSpace(identityID) == "" {
			continue
		}
		identityIDs = append(identityIDs, identityID)
	}
	return identityIDs
}

func apiMgmtRowHasIdentityContext(row map[string]any) bool {
	if row == nil {
		return false
	}
	rowIdentityType, _ := row["workload_identity_type"].(string)
	rowPrincipalID, _ := row["workload_principal_id"].(string)
	rowClientID, _ := row["workload_client_id"].(string)
	return normalizeIdentityType(rowIdentityType) != "" ||
		strings.TrimSpace(rowPrincipalID) != "" ||
		strings.TrimSpace(rowClientID) != "" ||
		len(apiMgmtRowIdentityIDs(row)) > 0
}

func validateACRPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveACRContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "acr" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-acr-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live acr context artifact",
			"lab runner acr context capture",
			"acr validation should compare the tool payload against recorded Azure Container Registry truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.Registries {
		row := findACRRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-registry-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible container registry row for id %q", label, truth.ID),
				"acr asset visibility or Azure-backed validation context",
				"acr should keep visible Azure Container Registry assets visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowName, _ := row["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q as name %q, but Azure reports %q", label, truth.ID, rowName, truth.Name),
				"acr naming or Azure-backed validation context",
				"acr should keep the registry name aligned with the Azure asset it is summarizing",
			))
		}

		rowResourceGroup, _ := row["resource_group"].(string)
		if strings.TrimSpace(truth.ResourceGroup) != "" && strings.TrimSpace(rowResourceGroup) != strings.TrimSpace(truth.ResourceGroup) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-resource-group-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with resource_group %q, but Azure reports %q", label, truth.ID, rowResourceGroup, truth.ResourceGroup),
				"acr resource-group rendering or Azure-backed validation context",
				"acr should keep the resource group aligned with the Azure registry it is summarizing",
			))
		}

		rowLocation, _ := row["location"].(string)
		if strings.TrimSpace(truth.Location) != "" && strings.TrimSpace(rowLocation) != strings.TrimSpace(truth.Location) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-location-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with location %q, but Azure reports %q", label, truth.ID, rowLocation, truth.Location),
				"acr location rendering or Azure-backed validation context",
				"acr should keep the registry location aligned with the Azure asset it is summarizing",
			))
		}

		rowState, _ := row["state"].(string)
		if strings.TrimSpace(truth.State) != "" && !strings.EqualFold(strings.TrimSpace(rowState), strings.TrimSpace(truth.State)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-state-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with state %q, but Azure reports %q", label, truth.ID, rowState, truth.State),
				"acr runtime rendering or Azure-backed validation context",
				"acr should keep provisioning state aligned with the Azure registry it is summarizing",
			))
		}

		rowLoginServer, _ := row["login_server"].(string)
		if strings.TrimSpace(truth.LoginServer) != "" && strings.TrimSpace(rowLoginServer) != strings.TrimSpace(truth.LoginServer) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-login-server-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with login_server %q, but Azure reports %q", label, truth.ID, rowLoginServer, truth.LoginServer),
				"acr login server rendering or Azure-backed validation context",
				"acr should keep the visible login server aligned with the Azure registry truth",
			))
		}

		rowSKUName, _ := row["sku_name"].(string)
		if strings.TrimSpace(truth.SKUName) != "" && !strings.EqualFold(strings.TrimSpace(rowSKUName), strings.TrimSpace(truth.SKUName)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-sku-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with sku_name %q, but Azure reports %q", label, truth.ID, rowSKUName, truth.SKUName),
				"acr sku rendering or Azure-backed validation context",
				"acr should keep the registry SKU aligned with the Azure asset it is summarizing",
			))
		}

		rowPublicNetworkAccess, _ := row["public_network_access"].(string)
		if strings.TrimSpace(truth.PublicNetworkAccess) != "" && !strings.EqualFold(strings.TrimSpace(rowPublicNetworkAccess), strings.TrimSpace(truth.PublicNetworkAccess)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-public-network-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with public_network_access %q, but Azure reports %q", label, truth.ID, rowPublicNetworkAccess, truth.PublicNetworkAccess),
				"acr public network posture or Azure-backed validation context",
				"acr should keep the public network posture aligned with the Azure registry it is summarizing",
			))
		}

		rowNetworkRuleDefaultAction, _ := row["network_rule_default_action"].(string)
		if strings.TrimSpace(truth.NetworkRuleDefaultAction) != "" && !strings.EqualFold(strings.TrimSpace(rowNetworkRuleDefaultAction), strings.TrimSpace(truth.NetworkRuleDefaultAction)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-network-default-action-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with network_rule_default_action %q, but Azure reports %q", label, truth.ID, rowNetworkRuleDefaultAction, truth.NetworkRuleDefaultAction),
				"acr network rule rendering or Azure-backed validation context",
				"acr should keep the default network rule action aligned with the Azure registry it is summarizing",
			))
		}

		rowNetworkRuleBypassOptions, _ := row["network_rule_bypass_options"].(string)
		if strings.TrimSpace(truth.NetworkRuleBypassOptions) != "" && !strings.EqualFold(strings.TrimSpace(rowNetworkRuleBypassOptions), strings.TrimSpace(truth.NetworkRuleBypassOptions)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-network-bypass-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with network_rule_bypass_options %q, but Azure reports %q", label, truth.ID, rowNetworkRuleBypassOptions, truth.NetworkRuleBypassOptions),
				"acr network bypass rendering or Azure-backed validation context",
				"acr should keep the network bypass posture aligned with the Azure registry it is summarizing",
			))
		}

		checkBool := func(key string, truthValue *bool, seam, expected string) {
			if truthValue == nil {
				return
			}
			rowValue := rowBoolPtr(row, key)
			observed := "<missing>"
			if rowValue != nil {
				observed = fmt.Sprintf("%v", *rowValue)
			}
			if rowValue == nil || *rowValue != *truthValue {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s surfaced registry id %q with %s %s, but Azure reports %v", label, truth.ID, key, observed, *truthValue),
					seam,
					expected,
				))
			}
		}
		checkBool("admin_user_enabled", truth.AdminUserEnabled, "acr auth rendering or Azure-backed validation context", "acr should keep admin-user posture aligned with the Azure registry it is summarizing")
		checkBool("anonymous_pull_enabled", truth.AnonymousPullEnabled, "acr auth rendering or Azure-backed validation context", "acr should keep anonymous-pull posture aligned with the Azure registry it is summarizing")
		checkBool("data_endpoint_enabled", truth.DataEndpointEnabled, "acr service-shape rendering or Azure-backed validation context", "acr should keep data endpoint posture aligned with the Azure registry it is summarizing")

		checkInt := func(key string, truthValue *int, seam, expected string) {
			if truthValue == nil {
				return
			}
			rowValue := rowIntPtr(row, key)
			observed := "<missing>"
			if rowValue != nil {
				observed = fmt.Sprintf("%d", *rowValue)
			}
			if rowValue == nil || *rowValue != *truthValue {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s surfaced registry id %q with %s %s, but Azure reports %d", label, truth.ID, key, observed, *truthValue),
					seam,
					expected,
				))
			}
		}
		checkInt("private_endpoint_connection_count", truth.PrivateEndpointConnectionCount, "acr endpoint rendering or Azure-backed validation context", "acr should keep private endpoint counts aligned with the Azure registry it is summarizing")
		checkInt("webhook_count", truth.WebhookCount, "acr webhook rendering or Azure-backed validation context", "acr should keep webhook counts aligned with the Azure registry it is summarizing")
		checkInt("enabled_webhook_count", truth.EnabledWebhookCount, "acr webhook rendering or Azure-backed validation context", "acr should keep enabled webhook counts aligned with the Azure registry it is summarizing")
		checkInt("broad_webhook_scope_count", truth.BroadWebhookScopeCount, "acr webhook scope rendering or Azure-backed validation context", "acr should keep broad webhook scope counts aligned with the Azure registry it is summarizing")
		checkInt("replication_count", truth.ReplicationCount, "acr replication rendering or Azure-backed validation context", "acr should keep replication counts aligned with the Azure registry it is summarizing")
		checkInt("retention_policy_days", truth.RetentionPolicyDays, "acr retention rendering or Azure-backed validation context", "acr should keep retention policy days aligned with the Azure registry it is summarizing")

		rowQuarantinePolicyStatus, _ := row["quarantine_policy_status"].(string)
		if strings.TrimSpace(truth.QuarantinePolicyStatus) != "" && !strings.EqualFold(strings.TrimSpace(rowQuarantinePolicyStatus), strings.TrimSpace(truth.QuarantinePolicyStatus)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-quarantine-policy-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with quarantine_policy_status %q, but Azure reports %q", label, truth.ID, rowQuarantinePolicyStatus, truth.QuarantinePolicyStatus),
				"acr quarantine policy rendering or Azure-backed validation context",
				"acr should keep quarantine policy posture aligned with the Azure registry it is summarizing",
			))
		}

		rowRetentionPolicyStatus, _ := row["retention_policy_status"].(string)
		if strings.TrimSpace(truth.RetentionPolicyStatus) != "" && !strings.EqualFold(strings.TrimSpace(rowRetentionPolicyStatus), strings.TrimSpace(truth.RetentionPolicyStatus)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-retention-policy-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with retention_policy_status %q, but Azure reports %q", label, truth.ID, rowRetentionPolicyStatus, truth.RetentionPolicyStatus),
				"acr retention policy rendering or Azure-backed validation context",
				"acr should keep retention policy posture aligned with the Azure registry it is summarizing",
			))
		}

		rowTrustPolicyStatus, _ := row["trust_policy_status"].(string)
		if strings.TrimSpace(truth.TrustPolicyStatus) != "" && !strings.EqualFold(strings.TrimSpace(rowTrustPolicyStatus), strings.TrimSpace(truth.TrustPolicyStatus)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-trust-policy-status-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with trust_policy_status %q, but Azure reports %q", label, truth.ID, rowTrustPolicyStatus, truth.TrustPolicyStatus),
				"acr trust policy rendering or Azure-backed validation context",
				"acr should keep trust policy posture aligned with the Azure registry it is summarizing",
			))
		}

		rowTrustPolicyType, _ := row["trust_policy_type"].(string)
		if strings.TrimSpace(truth.TrustPolicyType) != "" && !strings.EqualFold(strings.TrimSpace(rowTrustPolicyType), strings.TrimSpace(truth.TrustPolicyType)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-trust-policy-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with trust_policy_type %q, but Azure reports %q", label, truth.ID, rowTrustPolicyType, truth.TrustPolicyType),
				"acr trust policy rendering or Azure-backed validation context",
				"acr should keep trust policy type aligned with the Azure registry it is summarizing",
			))
		}

		expectedWebhookActionTypes := normalizeLowerStringSet(truth.WebhookActionTypes)
		if len(expectedWebhookActionTypes) > 0 {
			observedWebhookActionTypes := normalizeLowerStringSet(rowStringList(row, "webhook_action_types"))
			missingWebhookActions := []string{}
			for _, expectedWebhookAction := range truth.WebhookActionTypes {
				if _, ok := observedWebhookActionTypes[strings.ToLower(strings.TrimSpace(expectedWebhookAction))]; !ok {
					missingWebhookActions = append(missingWebhookActions, expectedWebhookAction)
				}
			}
			if len(missingWebhookActions) > 0 {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-webhook-action-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s lost Azure-visible webhook action types for registry id %q: %s", label, truth.ID, strings.Join(missingWebhookActions, ", ")),
					"acr webhook action rendering or Azure-backed validation context",
					"acr should preserve the webhook action types Azure currently shows on visible registries",
				))
			}
		}

		expectedReplicationRegions := normalizeLowerStringSet(truth.ReplicationRegions)
		if len(expectedReplicationRegions) > 0 {
			observedReplicationRegions := normalizeLowerStringSet(rowStringList(row, "replication_regions"))
			missingReplicationRegions := []string{}
			for _, expectedRegion := range truth.ReplicationRegions {
				if _, ok := observedReplicationRegions[strings.ToLower(strings.TrimSpace(expectedRegion))]; !ok {
					missingReplicationRegions = append(missingReplicationRegions, expectedRegion)
				}
			}
			if len(missingReplicationRegions) > 0 {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-replication-region-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s lost Azure-visible replication regions for registry id %q: %s", label, truth.ID, strings.Join(missingReplicationRegions, ", ")),
					"acr replication rendering or Azure-backed validation context",
					"acr should preserve the replication regions Azure currently shows on visible registries",
				))
			}
		}

		if normalizeIdentityType(truth.IdentityType) == "" && len(truth.IdentityIDs) == 0 && strings.TrimSpace(truth.WorkloadPrincipalID) == "" && strings.TrimSpace(truth.WorkloadClientID) == "" {
			if acrRowHasIdentityContext(row) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-identity-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced registry id %q with managed identity context, but Azure does not currently show identity on that registry", label, truth.ID),
					"acr identity rendering or Azure-backed validation context",
					"acr should not describe a registry as identity-bearing when Azure shows no managed identity on that registry",
				))
			}
			continue
		}

		if !acrRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q, but lost the Azure-visible identity context for that registry", label, truth.ID),
				"acr identity rendering or Azure-backed validation context",
				"acr should preserve managed identity context when Azure shows that registry carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["workload_identity_type"].(string)
		if normalizeIdentityType(truth.IdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.IdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with workload_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.IdentityType),
				"acr identity typing or Azure-backed validation context",
				"acr should keep registry identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		rowPrincipalID, _ := row["workload_principal_id"].(string)
		if strings.TrimSpace(truth.WorkloadPrincipalID) != "" && strings.TrimSpace(rowPrincipalID) != strings.TrimSpace(truth.WorkloadPrincipalID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with workload_principal_id %q, but Azure reports %q", label, truth.ID, rowPrincipalID, truth.WorkloadPrincipalID),
				"acr identity rendering or Azure-backed validation context",
				"acr should keep registry principal IDs aligned with the Azure identity configuration it is summarizing",
			))
		}

		rowClientID, _ := row["workload_client_id"].(string)
		if strings.TrimSpace(truth.WorkloadClientID) != "" && strings.TrimSpace(rowClientID) != strings.TrimSpace(truth.WorkloadClientID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-client-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced registry id %q with workload_client_id %q, but Azure reports %q", label, truth.ID, rowClientID, truth.WorkloadClientID),
				"acr identity rendering or Azure-backed validation context",
				"acr should keep registry client IDs aligned with the Azure identity configuration it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		if len(expectedIdentityIDs) == 0 {
			continue
		}
		observedIdentityIDs := normalizeStringSet(acrRowIdentityIDs(row))
		missingIdentityIDs := []string{}
		for _, expectedIdentityID := range truth.IdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
				missingIdentityIDs = append(missingIdentityIDs, expectedIdentityID)
			}
		}
		if len(missingIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s lost Azure-visible registry identity IDs for id %q: %s", label, truth.ID, strings.Join(missingIdentityIDs, ", ")),
				"acr user-assigned identity rendering or Azure-backed validation context",
				"acr should preserve the user-assigned identity IDs Azure currently shows on visible registries",
			))
		}
	}

	return findings
}

func validateApplicationGatewayPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveApplicationGatewayContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "application-gateway" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-application-gateway-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live application-gateway context artifact",
			"lab runner application-gateway context capture",
			"application-gateway validation should compare the tool payload against recorded Azure Application Gateway truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["application_gateways"].([]any)
	if len(rows) != len(context.ApplicationGateways) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d application-gateway rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.ApplicationGateways)),
			"application-gateway row selection or Azure-backed validation context",
			"application-gateway should keep visible gateway rows aligned with the Azure gateways the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.ApplicationGateways {
		row := findApplicationGatewayRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-gateway-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible Application Gateway row for id %q", label, truth.ID),
				"application-gateway asset visibility or Azure-backed validation context",
				"application-gateway should keep visible Azure Application Gateway assets visible when the current viewpoint can enumerate them",
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
				fmt.Sprintf("%s surfaced Application Gateway id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
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
				fmt.Sprintf("%s surfaced Application Gateway id %q with %s %d, but Azure reports %d", label, truth.ID, field, int(observed), expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkString("name", truth.Name, "application-gateway naming or Azure-backed validation context", "application-gateway should keep the gateway name aligned with the Azure asset it is summarizing")
		checkString("resource_group", truth.ResourceGroup, "application-gateway resource-group rendering or Azure-backed validation context", "application-gateway should keep the resource group aligned with the Azure gateway it is summarizing")
		checkString("location", truth.Location, "application-gateway location rendering or Azure-backed validation context", "application-gateway should keep the gateway location aligned with the Azure asset it is summarizing")
		checkString("state", truth.State, "application-gateway runtime rendering or Azure-backed validation context", "application-gateway should keep operational state aligned with the Azure gateway it is summarizing")
		checkString("firewall_policy_id", truth.FirewallPolicyID, "application-gateway WAF attachment rendering or Azure-backed validation context", "application-gateway should keep the attached firewall policy aligned with the Azure gateway it is summarizing")
		checkInt("public_frontend_count", truth.PublicFrontendCount, "application-gateway public edge rendering or Azure-backed validation context", "application-gateway should keep public frontend counts aligned with the Azure gateway it is summarizing")
		checkInt("listener_count", truth.ListenerCount, "application-gateway routing breadth rendering or Azure-backed validation context", "application-gateway should keep listener counts aligned with the Azure gateway it is summarizing")
		checkInt("request_routing_rule_count", truth.RequestRoutingRuleCount, "application-gateway routing breadth rendering or Azure-backed validation context", "application-gateway should keep routing-rule counts aligned with the Azure gateway it is summarizing")
		checkInt("backend_pool_count", truth.BackendPoolCount, "application-gateway backend rendering or Azure-backed validation context", "application-gateway should keep backend-pool counts aligned with the Azure gateway it is summarizing")
		checkInt("backend_target_count", truth.BackendTargetCount, "application-gateway backend rendering or Azure-backed validation context", "application-gateway should keep backend-target counts aligned with the Azure gateway it is summarizing")

		expectedPublicIPs := normalizePlainStringSet(truth.PublicIPAddresses)
		observedPublicIPs := normalizePlainStringSet(rowStringList(row, "public_ip_addresses"))
		publicIPsMatch := len(expectedPublicIPs) == len(observedPublicIPs)
		if publicIPsMatch {
			for expectedPublicIP := range expectedPublicIPs {
				if _, ok := observedPublicIPs[expectedPublicIP]; !ok {
					publicIPsMatch = false
					break
				}
			}
		}
		if len(expectedPublicIPs) > 0 && !publicIPsMatch {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-public-ip-addresses-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Application Gateway id %q with public_ip_addresses %v, but Azure reports %v", label, truth.ID, rowStringList(row, "public_ip_addresses"), truth.PublicIPAddresses),
				"application-gateway public IP rendering or Azure-backed validation context",
				"application-gateway should keep visible public frontend IP addresses aligned with the Azure gateway it is summarizing",
			))
		}

		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-id-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced Application Gateway id %q with related_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
				"application-gateway related-id rendering or Azure-backed validation context",
				"application-gateway should preserve the gateway, public IP, and firewall policy IDs that support the visible ingress story",
			))
			break
		}
	}

	return findings
}

func validateAPIMgmtPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAPIMgmtContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "api-mgmt" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-api-mgmt-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live api-mgmt context artifact",
			"lab runner api-mgmt context capture",
			"api-mgmt validation should compare the tool payload against recorded Azure API Management truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["api_management_services"].([]any)
	if len(rows) != len(context.Services) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d api-mgmt rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.Services)),
			"api-mgmt row selection or Azure-backed validation context",
			"api-mgmt should keep visible API Management rows aligned with the Azure services the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.Services {
		row := findAPIMgmtRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-service-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible API Management row for id %q", label, truth.ID),
				"api-mgmt asset visibility or Azure-backed validation context",
				"api-mgmt should keep visible Azure API Management services visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkOptionalString := func(field string, expected string, equalFold bool, likelySeam string, expectedOutcome string) {
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
				fmt.Sprintf("%s surfaced API Management id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkIntPtr := func(field string, expected *int, likelySeam string, expectedOutcome string) {
			if expected == nil {
				return
			}
			observed := rowIntPtr(row, field)
			if observed != nil && *observed == *expected {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced API Management id %q with %s %v, but Azure reports %d", label, truth.ID, field, row[field], *expected),
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
				fmt.Sprintf("%s surfaced API Management id %q with %s %v, but Azure reports %t", label, truth.ID, field, row[field], *expected),
				likelySeam,
				expectedOutcome,
			))
		}
		checkStringList := func(field string, expected []string, normalizeLower bool, likelySeam string, expectedOutcome string) {
			observedValues := rowStringList(row, field)
			var expectedSet map[string]struct{}
			var observedSet map[string]struct{}
			if normalizeLower {
				expectedSet = normalizeLowerStringSet(expected)
				observedSet = normalizeLowerStringSet(observedValues)
			} else {
				expectedSet = normalizePlainStringSet(expected)
				observedSet = normalizePlainStringSet(observedValues)
			}
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
				fmt.Sprintf("%s surfaced API Management id %q with %s %v, but Azure reports %v", label, truth.ID, field, observedValues, expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkOptionalString("name", truth.Name, false, "api-mgmt naming or Azure-backed validation context", "api-mgmt should keep the service name aligned with the Azure asset it is summarizing")
		checkOptionalString("resource_group", truth.ResourceGroup, true, "api-mgmt resource-group rendering or Azure-backed validation context", "api-mgmt should keep the service resource group aligned with the Azure asset it is summarizing")
		checkOptionalString("location", truth.Location, true, "api-mgmt location rendering or Azure-backed validation context", "api-mgmt should keep the service location aligned with the Azure asset it is summarizing")
		checkOptionalString("state", truth.State, true, "api-mgmt state rendering or Azure-backed validation context", "api-mgmt should keep the service provisioning state aligned with the Azure asset it is summarizing")
		checkOptionalString("sku_name", truth.SKUName, true, "api-mgmt SKU rendering or Azure-backed validation context", "api-mgmt should keep the service SKU aligned with the Azure asset it is summarizing")
		checkOptionalString("public_network_access", truth.PublicNetworkAccess, true, "api-mgmt public network posture or Azure-backed validation context", "api-mgmt should keep the public network posture aligned with the Azure service it is summarizing")
		checkOptionalString("virtual_network_type", truth.VirtualNetworkType, true, "api-mgmt virtual network posture or Azure-backed validation context", "api-mgmt should keep the virtual network posture aligned with the Azure service it is summarizing")
		checkOptionalString("public_ip_address_id", truth.PublicIPAddressID, false, "api-mgmt public IP join rendering or Azure-backed validation context", "api-mgmt should keep the public IP attachment aligned with the Azure service it is summarizing")

		checkIntPtr("sku_capacity", truth.SKUCapacity, "api-mgmt SKU capacity rendering or Azure-backed validation context", "api-mgmt should keep the visible SKU capacity aligned with the Azure service it is summarizing")
		checkBoolPtr("gateway_enabled", truth.GatewayEnabled, "api-mgmt gateway posture or Azure-backed validation context", "api-mgmt should keep the gateway-enabled posture aligned with the Azure service it is summarizing")
		checkIntPtr("api_count", truth.APICount, "api-mgmt API inventory counting or Azure-backed validation context", "api-mgmt should keep visible API inventory counts aligned with Azure")
		checkIntPtr("api_subscription_required_count", truth.APISubscriptionRequiredCount, "api-mgmt API subscription posture or Azure-backed validation context", "api-mgmt should keep subscription-required API counts aligned with Azure")
		checkIntPtr("subscription_count", truth.SubscriptionCount, "api-mgmt subscription inventory counting or Azure-backed validation context", "api-mgmt should keep visible subscription counts aligned with Azure")
		checkIntPtr("active_subscription_count", truth.ActiveSubscriptionCount, "api-mgmt active subscription counting or Azure-backed validation context", "api-mgmt should keep active subscription counts aligned with Azure")
		checkIntPtr("backend_count", truth.BackendCount, "api-mgmt backend inventory counting or Azure-backed validation context", "api-mgmt should keep backend counts aligned with Azure")
		checkIntPtr("named_value_count", truth.NamedValueCount, "api-mgmt named-value inventory counting or Azure-backed validation context", "api-mgmt should keep named value counts aligned with Azure")
		checkIntPtr("named_value_secret_count", truth.NamedValueSecretCount, "api-mgmt named-value secret posture or Azure-backed validation context", "api-mgmt should keep secret-marked named value counts aligned with Azure")
		checkIntPtr("named_value_key_vault_count", truth.NamedValueKeyVaultCount, "api-mgmt named-value key-vault posture or Azure-backed validation context", "api-mgmt should keep Key Vault-backed named value counts aligned with Azure")

		checkStringList("public_ip_addresses", truth.PublicIPAddresses, false, "api-mgmt public IP rendering or Azure-backed validation context", "api-mgmt should keep public IP addresses aligned with the Azure service it is summarizing")
		checkStringList("private_ip_addresses", truth.PrivateIPAddresses, false, "api-mgmt private IP rendering or Azure-backed validation context", "api-mgmt should keep private IP addresses aligned with the Azure service it is summarizing")
		checkStringList("gateway_hostnames", truth.GatewayHostnames, true, "api-mgmt gateway hostname rendering or Azure-backed validation context", "api-mgmt should keep gateway hostnames aligned with the Azure service it is summarizing")
		if len(truth.ManagementHostnames) > 0 {
			checkStringList("management_hostnames", truth.ManagementHostnames, true, "api-mgmt management hostname rendering or Azure-backed validation context", "api-mgmt should keep management hostnames aligned with the Azure service it is summarizing")
		}
		if len(truth.PortalHostnames) > 0 {
			checkStringList("portal_hostnames", truth.PortalHostnames, true, "api-mgmt portal hostname rendering or Azure-backed validation context", "api-mgmt should keep portal hostnames aligned with the Azure service it is summarizing")
		}
		checkStringList("backend_hostnames", truth.BackendHostnames, true, "api-mgmt backend hostname rendering or Azure-backed validation context", "api-mgmt should keep backend hostnames aligned with the Azure service it is summarizing")

		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-id-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced API Management id %q with related_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
				"api-mgmt related-id rendering or Azure-backed validation context",
				"api-mgmt should preserve the service and visible identity join IDs that support the summarized posture",
			))
			break
		}

		if normalizeIdentityType(truth.WorkloadIdentityType) == "" && len(truth.WorkloadIdentityIDs) == 0 && strings.TrimSpace(truth.WorkloadPrincipalID) == "" && strings.TrimSpace(truth.WorkloadClientID) == "" {
			continue
		}
		if !apiMgmtRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced API Management id %q, but lost the Azure-visible identity context for that service", label, truth.ID),
				"api-mgmt identity rendering or Azure-backed validation context",
				"api-mgmt should preserve managed identity context when Azure shows that service carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["workload_identity_type"].(string)
		if normalizeIdentityType(truth.WorkloadIdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.WorkloadIdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced API Management id %q with workload_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.WorkloadIdentityType),
				"api-mgmt identity typing or Azure-backed validation context",
				"api-mgmt should keep API Management identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		rowPrincipalID, _ := row["workload_principal_id"].(string)
		if strings.TrimSpace(truth.WorkloadPrincipalID) != "" && strings.TrimSpace(rowPrincipalID) != strings.TrimSpace(truth.WorkloadPrincipalID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced API Management id %q with workload_principal_id %q, but Azure reports %q", label, truth.ID, rowPrincipalID, truth.WorkloadPrincipalID),
				"api-mgmt identity principal rendering or Azure-backed validation context",
				"api-mgmt should keep the service workload principal id aligned with the Azure identity configuration it is summarizing",
			))
		}

		rowClientID, _ := row["workload_client_id"].(string)
		if strings.TrimSpace(truth.WorkloadClientID) != "" && strings.TrimSpace(rowClientID) != strings.TrimSpace(truth.WorkloadClientID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-client-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced API Management id %q with workload_client_id %q, but Azure reports %q", label, truth.ID, rowClientID, truth.WorkloadClientID),
				"api-mgmt identity client rendering or Azure-backed validation context",
				"api-mgmt should keep the service workload client id aligned with the Azure identity configuration it is summarizing",
			))
		}

		observedIdentityIDs := normalizeStringSet(apiMgmtRowIdentityIDs(row))
		for _, expectedIdentityID := range truth.WorkloadIdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced API Management id %q with workload_identity_ids %v, but Azure reports %v", label, truth.ID, apiMgmtRowIdentityIDs(row), truth.WorkloadIdentityIDs),
				"api-mgmt identity join rendering or Azure-backed validation context",
				"api-mgmt should keep user-assigned identity ids aligned with the Azure service identity configuration it is summarizing",
			))
			break
		}
	}

	return findings
}

func validateDatabasesPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveDatabasesContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "databases" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-databases-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live databases context artifact",
			"lab runner databases context capture",
			"databases validation should compare the tool payload against recorded Azure database truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	rows, _ := payload["database_servers"].([]any)
	if len(rows) != len(context.DatabaseServers) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s surfaced %d database rows, but Azure-backed validation recorded %d visible rows", label, len(rows), len(context.DatabaseServers)),
			"databases row selection or Azure-backed validation context",
			"databases should keep visible database server rows aligned with the Azure servers the current viewpoint can enumerate",
		))
	}

	for _, truth := range context.DatabaseServers {
		row := findDatabaseServerRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-database-server-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible database server row for id %q", label, truth.ID),
				"databases asset visibility or Azure-backed validation context",
				"databases should keep visible Azure database servers visible when the current viewpoint can enumerate them",
			))
			continue
		}

		checkOptionalString := func(field string, expected string, equalFold bool, likelySeam string, expectedOutcome string) {
			observed, _ := row[field].(string)
			if strings.TrimSpace(expected) == "" {
				return
			}
			if equalFold {
				if strings.EqualFold(strings.TrimSpace(observed), strings.TrimSpace(expected)) {
					return
				}
			} else if strings.TrimSpace(observed) == strings.TrimSpace(expected) {
				return
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(field, "_", "-")),
				fmt.Sprintf("%s surfaced database server id %q with %s %q, but Azure reports %q", label, truth.ID, field, observed, expected),
				likelySeam,
				expectedOutcome,
			))
		}

		checkOptionalString("name", truth.Name, false, "databases naming or Azure-backed validation context", "databases should keep the server name aligned with the Azure asset it is summarizing")
		checkOptionalString("resource_group", truth.ResourceGroup, true, "databases resource-group rendering or Azure-backed validation context", "databases should keep the server resource group aligned with the Azure asset it is summarizing")
		checkOptionalString("location", truth.Location, true, "databases location rendering or Azure-backed validation context", "databases should keep the server location aligned with the Azure asset it is summarizing")
		checkOptionalString("engine", truth.Engine, false, "databases engine rendering or Azure-backed validation context", "databases should keep the database engine aligned with the Azure server it is summarizing")
		checkOptionalString("fully_qualified_domain_name", truth.FullyQualifiedDomainName, false, "databases endpoint rendering or Azure-backed validation context", "databases should keep the visible database endpoint aligned with the Azure server it is summarizing")
		checkOptionalString("public_network_access", truth.PublicNetworkAccess, true, "databases public network posture or Azure-backed validation context", "databases should keep the public network posture aligned with the Azure server it is summarizing")
		checkOptionalString("minimal_tls_version", truth.MinimalTLSVersion, false, "databases TLS posture or Azure-backed validation context", "databases should keep the minimal TLS posture aligned with the Azure server it is summarizing")
		checkOptionalString("server_version", truth.ServerVersion, false, "databases version rendering or Azure-backed validation context", "databases should keep the server version aligned with the Azure server it is summarizing")
		checkOptionalString("state", truth.State, true, "databases state rendering or Azure-backed validation context", "databases should keep the server state aligned with the Azure server it is summarizing")

		if truth.DatabaseCount != nil {
			if observed := rowIntPtr(row, "database_count"); observed == nil || *observed != *truth.DatabaseCount {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-database-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced database server id %q with database_count %v, but Azure reports %d", label, truth.ID, row["database_count"], *truth.DatabaseCount),
					"databases visible inventory counting or Azure-backed validation context",
					"databases should keep visible user-database counts aligned with the Azure server it is summarizing",
				))
			}
		}

		expectedUserDatabaseNames := normalizeLowerStringSet(truth.UserDatabaseNames)
		observedUserDatabaseNames := normalizeLowerStringSet(rowStringList(row, "user_database_names"))
		userDatabaseNamesMatch := len(expectedUserDatabaseNames) == len(observedUserDatabaseNames)
		if userDatabaseNamesMatch {
			for expectedName := range expectedUserDatabaseNames {
				if _, ok := observedUserDatabaseNames[expectedName]; !ok {
					userDatabaseNamesMatch = false
					break
				}
			}
		}
		if !userDatabaseNamesMatch {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-user-database-names-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced database server id %q with user_database_names %v, but Azure reports %v", label, truth.ID, rowStringList(row, "user_database_names"), truth.UserDatabaseNames),
				"databases visible inventory rendering or Azure-backed validation context",
				"databases should keep visible user database names aligned with the Azure server it is summarizing",
			))
		}

		observedRelatedIDs := normalizeStringSet(rowStringList(row, "related_ids"))
		for _, expectedRelatedID := range truth.RelatedIDs {
			if _, ok := observedRelatedIDs[normalizeResourceID(expectedRelatedID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-related-id-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced database server id %q with related_ids %v, but Azure-backed expectation is %v", label, truth.ID, rowStringList(row, "related_ids"), truth.RelatedIDs),
				"databases related-id rendering or Azure-backed validation context",
				"databases should preserve the server and visible identity join IDs that support the summarized posture",
			))
			break
		}

		if normalizeIdentityType(truth.WorkloadIdentityType) == "" && len(truth.WorkloadIdentityIDs) == 0 && strings.TrimSpace(truth.WorkloadPrincipalID) == "" && strings.TrimSpace(truth.WorkloadClientID) == "" {
			continue
		}
		if !databaseRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced database server id %q, but lost the Azure-visible identity context for that server", label, truth.ID),
				"databases identity rendering or Azure-backed validation context",
				"databases should preserve managed identity context when Azure shows that server carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["workload_identity_type"].(string)
		if normalizeIdentityType(truth.WorkloadIdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.WorkloadIdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced database server id %q with workload_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.WorkloadIdentityType),
				"databases identity typing or Azure-backed validation context",
				"databases should keep database server identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		rowPrincipalID, _ := row["workload_principal_id"].(string)
		if strings.TrimSpace(truth.WorkloadPrincipalID) != "" && strings.TrimSpace(rowPrincipalID) != strings.TrimSpace(truth.WorkloadPrincipalID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced database server id %q with workload_principal_id %q, but Azure reports %q", label, truth.ID, rowPrincipalID, truth.WorkloadPrincipalID),
				"databases identity principal rendering or Azure-backed validation context",
				"databases should keep the server workload principal id aligned with the Azure identity configuration it is summarizing",
			))
		}

		rowClientID, _ := row["workload_client_id"].(string)
		if strings.TrimSpace(truth.WorkloadClientID) != "" && strings.TrimSpace(rowClientID) != strings.TrimSpace(truth.WorkloadClientID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-client-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced database server id %q with workload_client_id %q, but Azure reports %q", label, truth.ID, rowClientID, truth.WorkloadClientID),
				"databases identity client rendering or Azure-backed validation context",
				"databases should keep the server workload client id aligned with the Azure identity configuration it is summarizing",
			))
		}

		observedIdentityIDs := normalizeStringSet(databaseRowIdentityIDs(row))
		for _, expectedIdentityID := range truth.WorkloadIdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; ok {
				continue
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced database server id %q with workload_identity_ids %v, but Azure reports %v", label, truth.ID, databaseRowIdentityIDs(row), truth.WorkloadIdentityIDs),
				"databases identity join rendering or Azure-backed validation context",
				"databases should keep user-assigned identity ids aligned with the Azure server identity configuration it is summarizing",
			))
			break
		}
	}

	return findings
}

func validateAKSPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveAKSContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "aks" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-aks-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live aks context artifact",
			"lab runner aks context capture",
			"aks validation should compare the tool payload against recorded Azure AKS truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.AKSClusters {
		row := findAKSRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-cluster-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible AKS row for id %q", label, truth.ID),
				"aks asset visibility or Azure-backed validation context",
				"aks should keep visible Azure AKS clusters visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowName, _ := row["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q as name %q, but Azure reports %q", label, truth.ID, rowName, truth.Name),
				"aks naming or Azure-backed validation context",
				"aks should keep the cluster name aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowResourceGroup, _ := row["resource_group"].(string)
		if strings.TrimSpace(truth.ResourceGroup) != "" && strings.TrimSpace(rowResourceGroup) != strings.TrimSpace(truth.ResourceGroup) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-resource-group-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with resource_group %q, but Azure reports %q", label, truth.ID, rowResourceGroup, truth.ResourceGroup),
				"aks resource-group rendering or Azure-backed validation context",
				"aks should keep the resource group aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowLocation, _ := row["location"].(string)
		if strings.TrimSpace(truth.Location) != "" && strings.TrimSpace(rowLocation) != strings.TrimSpace(truth.Location) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-location-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with location %q, but Azure reports %q", label, truth.ID, rowLocation, truth.Location),
				"aks location rendering or Azure-backed validation context",
				"aks should keep the cluster location aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowProvisioningState, _ := row["provisioning_state"].(string)
		if strings.TrimSpace(truth.ProvisioningState) != "" && !strings.EqualFold(strings.TrimSpace(rowProvisioningState), strings.TrimSpace(truth.ProvisioningState)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-provisioning-state-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with provisioning_state %q, but Azure reports %q", label, truth.ID, rowProvisioningState, truth.ProvisioningState),
				"aks runtime rendering or Azure-backed validation context",
				"aks should keep provisioning state aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowVersion, _ := row["kubernetes_version"].(string)
		if strings.TrimSpace(truth.KubernetesVersion) != "" && strings.TrimSpace(rowVersion) != strings.TrimSpace(truth.KubernetesVersion) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-version-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with kubernetes_version %q, but Azure reports %q", label, truth.ID, rowVersion, truth.KubernetesVersion),
				"aks version rendering or Azure-backed validation context",
				"aks should keep the Kubernetes version aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowSKUTier, _ := row["sku_tier"].(string)
		if strings.TrimSpace(truth.SKUTier) != "" && !strings.EqualFold(strings.TrimSpace(rowSKUTier), strings.TrimSpace(truth.SKUTier)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-sku-tier-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with sku_tier %q, but Azure reports %q", label, truth.ID, rowSKUTier, truth.SKUTier),
				"aks sku rendering or Azure-backed validation context",
				"aks should keep the SKU tier aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowNodeResourceGroup, _ := row["node_resource_group"].(string)
		if strings.TrimSpace(truth.NodeResourceGroup) != "" && strings.TrimSpace(rowNodeResourceGroup) != strings.TrimSpace(truth.NodeResourceGroup) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-node-resource-group-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with node_resource_group %q, but Azure reports %q", label, truth.ID, rowNodeResourceGroup, truth.NodeResourceGroup),
				"aks network rendering or Azure-backed validation context",
				"aks should keep the node resource group aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowFQDN, _ := row["fqdn"].(string)
		if strings.TrimSpace(truth.FQDN) != "" && strings.TrimSpace(rowFQDN) != strings.TrimSpace(truth.FQDN) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-fqdn-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with fqdn %q, but Azure reports %q", label, truth.ID, rowFQDN, truth.FQDN),
				"aks endpoint rendering or Azure-backed validation context",
				"aks should keep the visible control-plane FQDN aligned with the Azure AKS truth",
			))
		}

		rowLocalAccountsDisabled := rowBoolPtr(row, "local_accounts_disabled")
		if truth.LocalAccountsDisabled != nil {
			observedLocalAccountsDisabled := "<missing>"
			if rowLocalAccountsDisabled != nil {
				observedLocalAccountsDisabled = fmt.Sprintf("%v", *rowLocalAccountsDisabled)
			}
			if rowLocalAccountsDisabled == nil || *rowLocalAccountsDisabled != *truth.LocalAccountsDisabled {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-local-accounts-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced AKS id %q with local_accounts_disabled %s, but Azure reports %v", label, truth.ID, observedLocalAccountsDisabled, *truth.LocalAccountsDisabled),
					"aks auth rendering or Azure-backed validation context",
					"aks should keep local account posture aligned with the Azure AKS asset it is summarizing",
				))
			}
		}

		rowNetworkPlugin, _ := row["network_plugin"].(string)
		if strings.TrimSpace(truth.NetworkPlugin) != "" && !strings.EqualFold(strings.TrimSpace(rowNetworkPlugin), strings.TrimSpace(truth.NetworkPlugin)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-network-plugin-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with network_plugin %q, but Azure reports %q", label, truth.ID, rowNetworkPlugin, truth.NetworkPlugin),
				"aks network rendering or Azure-backed validation context",
				"aks should keep the network plugin aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowNetworkPolicy, _ := row["network_policy"].(string)
		if strings.TrimSpace(truth.NetworkPolicy) != "" && !strings.EqualFold(strings.TrimSpace(rowNetworkPolicy), strings.TrimSpace(truth.NetworkPolicy)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-network-policy-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with network_policy %q, but Azure reports %q", label, truth.ID, rowNetworkPolicy, truth.NetworkPolicy),
				"aks network rendering or Azure-backed validation context",
				"aks should keep the network policy aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowOutboundType, _ := row["outbound_type"].(string)
		if strings.TrimSpace(truth.OutboundType) != "" && !strings.EqualFold(strings.TrimSpace(rowOutboundType), strings.TrimSpace(truth.OutboundType)) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-outbound-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with outbound_type %q, but Azure reports %q", label, truth.ID, rowOutboundType, truth.OutboundType),
				"aks network rendering or Azure-backed validation context",
				"aks should keep outbound type aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowAgentPoolCount := rowIntPtr(row, "agent_pool_count")
		if truth.AgentPoolCount != nil {
			observedAgentPoolCount := "<missing>"
			if rowAgentPoolCount != nil {
				observedAgentPoolCount = fmt.Sprintf("%d", *rowAgentPoolCount)
			}
			if rowAgentPoolCount == nil || *rowAgentPoolCount != *truth.AgentPoolCount {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-agent-pool-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced AKS id %q with agent_pool_count %s, but Azure reports %d", label, truth.ID, observedAgentPoolCount, *truth.AgentPoolCount),
					"aks inventory rendering or Azure-backed validation context",
					"aks should keep the agent pool count aligned with the Azure AKS asset it is summarizing",
				))
			}
		}

		rowOIDCIssuerEnabled := rowBoolPtr(row, "oidc_issuer_enabled")
		if truth.OIDCIssuerEnabled != nil {
			observedOIDCIssuerEnabled := "<missing>"
			if rowOIDCIssuerEnabled != nil {
				observedOIDCIssuerEnabled = fmt.Sprintf("%v", *rowOIDCIssuerEnabled)
			}
			if rowOIDCIssuerEnabled == nil || *rowOIDCIssuerEnabled != *truth.OIDCIssuerEnabled {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-oidc-enabled-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced AKS id %q with oidc_issuer_enabled %s, but Azure reports %v", label, truth.ID, observedOIDCIssuerEnabled, *truth.OIDCIssuerEnabled),
					"aks auth rendering or Azure-backed validation context",
					"aks should keep OIDC issuer posture aligned with the Azure AKS asset it is summarizing",
				))
			}
		}

		rowOIDCIssuerURL, _ := row["oidc_issuer_url"].(string)
		if strings.TrimSpace(truth.OIDCIssuerURL) != "" && strings.TrimSpace(rowOIDCIssuerURL) != strings.TrimSpace(truth.OIDCIssuerURL) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-oidc-url-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with oidc_issuer_url %q, but Azure reports %q", label, truth.ID, rowOIDCIssuerURL, truth.OIDCIssuerURL),
				"aks auth rendering or Azure-backed validation context",
				"aks should keep the OIDC issuer URL aligned with the Azure AKS asset it is summarizing",
			))
		}

		expectedAddons := normalizePlainStringSet(truth.AddonNames)
		observedAddons := normalizePlainStringSet(rowStringList(row, "addon_names"))
		if len(expectedAddons) != len(observedAddons) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-addon-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with addon_names %v, but Azure reports %v", label, truth.ID, rowStringList(row, "addon_names"), truth.AddonNames),
				"aks addon rendering or Azure-backed validation context",
				"aks should keep addon visibility aligned with the Azure AKS asset it is summarizing",
			))
		} else {
			for _, expectedAddon := range truth.AddonNames {
				if _, ok := observedAddons[expectedAddon]; !ok {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-addon-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s lost Azure-visible addon %q for AKS id %q", label, expectedAddon, truth.ID),
						"aks addon rendering or Azure-backed validation context",
						"aks should keep addon visibility aligned with the Azure AKS asset it is summarizing",
					))
				}
			}
		}

		if normalizeIdentityType(truth.ClusterIdentityType) == "" && strings.TrimSpace(truth.ClusterPrincipalID) == "" && len(truth.ClusterIdentityIDs) == 0 {
			if aksRowHasIdentityContext(row) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-identity-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced AKS id %q with cluster identity context, but Azure does not currently show identity on that cluster", label, truth.ID),
					"aks identity rendering or Azure-backed validation context",
					"aks should not describe a cluster as identity-bearing when Azure shows no cluster identity context",
				))
			}
			continue
		}

		if !aksRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q, but lost the Azure-visible cluster identity context", label, truth.ID),
				"aks identity rendering or Azure-backed validation context",
				"aks should preserve cluster identity context when Azure shows that AKS cluster carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["cluster_identity_type"].(string)
		if normalizeIdentityType(truth.ClusterIdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.ClusterIdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with cluster_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.ClusterIdentityType),
				"aks identity typing or Azure-backed validation context",
				"aks should keep cluster identity type aligned with the Azure AKS asset it is summarizing",
			))
		}

		rowPrincipalID, _ := row["cluster_principal_id"].(string)
		if strings.TrimSpace(truth.ClusterPrincipalID) != "" && strings.TrimSpace(rowPrincipalID) != strings.TrimSpace(truth.ClusterPrincipalID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-principal-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced AKS id %q with cluster_principal_id %q, but Azure reports %q", label, truth.ID, rowPrincipalID, truth.ClusterPrincipalID),
				"aks identity rendering or Azure-backed validation context",
				"aks should keep the cluster principal ID aligned with the Azure AKS asset it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.ClusterIdentityIDs)
		if len(expectedIdentityIDs) == 0 {
			continue
		}
		observedIdentityIDs := normalizeStringSet(aksRowIdentityIDs(row))
		missingIdentityIDs := []string{}
		for _, expectedIdentityID := range truth.ClusterIdentityIDs {
			if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
				missingIdentityIDs = append(missingIdentityIDs, expectedIdentityID)
			}
		}
		if len(missingIdentityIDs) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s lost Azure-visible cluster identity IDs for AKS id %q: %s", label, truth.ID, strings.Join(missingIdentityIDs, ", ")),
				"aks user-assigned identity rendering or Azure-backed validation context",
				"aks should preserve the user-assigned identity IDs Azure currently shows on visible AKS clusters",
			))
		}
	}

	return findings
}

func validateContainerInstancesPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveContainerInstancesContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "container-instances" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-container-instances-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live container instances context artifact",
			"lab runner container instances context capture",
			"container-instances validation should compare the tool payload against recorded Azure Container Instance truth instead of remembered rows",
		)}
	}

	findings := []Finding{}
	for _, truth := range context.ContainerInstances {
		row := findContainerInstanceRowByID(payload, truth.ID)
		if row == nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-container-instance-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s did not surface an Azure-visible container group row for id %q", label, truth.ID),
				"container-instances asset visibility or Azure-backed validation context",
				"container-instances should keep visible Azure container groups visible when the current viewpoint can enumerate them",
			))
			continue
		}

		rowName, _ := row["name"].(string)
		if strings.TrimSpace(rowName) != strings.TrimSpace(truth.Name) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-name-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q as name %q, but Azure reports %q", label, truth.ID, rowName, truth.Name),
				"container-instances naming or Azure-backed validation context",
				"container-instances should keep the container group name aligned with the Azure asset it is summarizing",
			))
		}

		rowPublicIPAddress, _ := row["public_ip_address"].(string)
		if strings.TrimSpace(truth.PublicIPAddress) != "" && strings.TrimSpace(rowPublicIPAddress) != strings.TrimSpace(truth.PublicIPAddress) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-public-ip-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with public_ip_address %q, but Azure reports %q", label, truth.ID, rowPublicIPAddress, truth.PublicIPAddress),
				"container-instances public endpoint rendering or Azure-backed validation context",
				"container-instances should keep the public IP aligned with the Azure container group it is summarizing",
			))
		}

		rowFQDN, _ := row["fqdn"].(string)
		if strings.TrimSpace(truth.FQDN) != "" && strings.TrimSpace(rowFQDN) != strings.TrimSpace(truth.FQDN) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-fqdn-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with fqdn %q, but Azure reports %q", label, truth.ID, rowFQDN, truth.FQDN),
				"container-instances endpoint rendering or Azure-backed validation context",
				"container-instances should keep the visible FQDN aligned with the Azure container group truth",
			))
		}

		observedPorts := rowIntList(row, "exposed_ports")
		if !slices.Equal(observedPorts, truth.ExposedPorts) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-exposed-ports-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with exposed_ports %v, but Azure reports %v", label, truth.ID, observedPorts, truth.ExposedPorts),
				"container-instances network rendering or Azure-backed validation context",
				"container-instances should keep exposed ports aligned with the Azure container group it is summarizing",
			))
		}

		rowRestartPolicy, _ := row["restart_policy"].(string)
		if strings.TrimSpace(truth.RestartPolicy) != "" && strings.TrimSpace(rowRestartPolicy) != strings.TrimSpace(truth.RestartPolicy) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-restart-policy-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with restart_policy %q, but Azure reports %q", label, truth.ID, rowRestartPolicy, truth.RestartPolicy),
				"container-instances runtime rendering or Azure-backed validation context",
				"container-instances should keep restart policy aligned with the Azure container group it is summarizing",
			))
		}

		rowOSType, _ := row["os_type"].(string)
		if strings.TrimSpace(truth.OSType) != "" && strings.TrimSpace(rowOSType) != strings.TrimSpace(truth.OSType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-os-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with os_type %q, but Azure reports %q", label, truth.ID, rowOSType, truth.OSType),
				"container-instances runtime rendering or Azure-backed validation context",
				"container-instances should keep OS type aligned with the Azure container group it is summarizing",
			))
		}

		rowProvisioningState, _ := row["provisioning_state"].(string)
		if strings.TrimSpace(truth.ProvisioningState) != "" && strings.TrimSpace(rowProvisioningState) != strings.TrimSpace(truth.ProvisioningState) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-provisioning-state-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with provisioning_state %q, but Azure reports %q", label, truth.ID, rowProvisioningState, truth.ProvisioningState),
				"container-instances runtime rendering or Azure-backed validation context",
				"container-instances should keep provisioning state aligned with the Azure container group it is summarizing",
			))
		}

		rowContainerCount := rowIntPtr(row, "container_count")
		if truth.ContainerCount > 0 && (rowContainerCount == nil || *rowContainerCount != truth.ContainerCount) {
			observedCount := "<missing>"
			if rowContainerCount != nil {
				observedCount = fmt.Sprintf("%d", *rowContainerCount)
			}
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-container-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with container_count %s, but Azure reports %d", label, truth.ID, observedCount, truth.ContainerCount),
				"container-instances runtime rendering or Azure-backed validation context",
				"container-instances should keep container count aligned with the Azure container group it is summarizing",
			))
		}

		expectedImages := normalizePlainStringSet(truth.ContainerImages)
		observedImages := normalizePlainStringSet(rowStringList(row, "container_images"))
		if len(expectedImages) != len(observedImages) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-container-images-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with container_images %v, but Azure reports %v", label, truth.ID, rowStringList(row, "container_images"), truth.ContainerImages),
				"container-instances runtime rendering or Azure-backed validation context",
				"container-instances should keep container images aligned with the Azure container group it is summarizing",
			))
		} else {
			for _, expectedImage := range truth.ContainerImages {
				if _, ok := observedImages[strings.TrimSpace(expectedImage)]; !ok {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-container-images-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced container group id %q with container_images %v, but Azure reports %v", label, truth.ID, rowStringList(row, "container_images"), truth.ContainerImages),
						"container-instances runtime rendering or Azure-backed validation context",
						"container-instances should keep container images aligned with the Azure container group it is summarizing",
					))
					break
				}
			}
		}

		expectedSubnetIDs := normalizeStringSet(truth.SubnetIDs)
		observedSubnetIDs := normalizeStringSet(rowStringList(row, "subnet_ids"))
		if len(expectedSubnetIDs) != len(observedSubnetIDs) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-subnet-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with subnet_ids %v, but Azure reports %v", label, truth.ID, rowStringList(row, "subnet_ids"), truth.SubnetIDs),
				"container-instances network rendering or Azure-backed validation context",
				"container-instances should keep subnet placement aligned with the Azure container group it is summarizing",
			))
		} else {
			for _, expectedSubnetID := range truth.SubnetIDs {
				if _, ok := observedSubnetIDs[normalizeResourceID(expectedSubnetID)]; !ok {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-subnet-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced container group id %q with subnet_ids %v, but Azure reports %v", label, truth.ID, rowStringList(row, "subnet_ids"), truth.SubnetIDs),
						"container-instances network rendering or Azure-backed validation context",
						"container-instances should keep subnet placement aligned with the Azure container group it is summarizing",
					))
					break
				}
			}
		}

		if normalizeIdentityType(truth.IdentityType) == "" && len(truth.IdentityIDs) == 0 {
			if containerInstanceRowHasIdentityContext(row) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-unexpected-identity-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					fmt.Sprintf("%s surfaced container group id %q with identity context, but Azure does not currently show identity on that container group", label, truth.ID),
					"container-instances identity rendering or Azure-backed validation context",
					"container-instances should not describe a container group as identity-bearing when Azure shows no managed identity on that group",
				))
			}
			continue
		}
		if !containerInstanceRowHasIdentityContext(row) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-context-missing", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q, but lost the Azure-visible identity context for that container group", label, truth.ID),
				"container-instances identity rendering or Azure-backed validation context",
				"container-instances should preserve managed identity context when Azure shows that container group carrying identity configuration",
			))
			continue
		}

		rowIdentityType, _ := row["workload_identity_type"].(string)
		if normalizeIdentityType(truth.IdentityType) != "" && normalizeIdentityType(rowIdentityType) != normalizeIdentityType(truth.IdentityType) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-type-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with workload_identity_type %q, but Azure reports %q", label, truth.ID, rowIdentityType, truth.IdentityType),
				"container-instances identity typing or Azure-backed validation context",
				"container-instances should keep container group identity type aligned with the Azure identity configuration it is summarizing",
			))
		}

		expectedIdentityIDs := normalizeStringSet(truth.IdentityIDs)
		observedIdentityIDs := normalizeStringSet(containerInstanceRowIdentityIDs(row))
		if len(expectedIdentityIDs) != len(observedIdentityIDs) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s surfaced container group id %q with workload_identity_ids %v, but Azure reports %v", label, truth.ID, containerInstanceRowIdentityIDs(row), truth.IdentityIDs),
				"container-instances user-assigned identity rendering or Azure-backed validation context",
				"container-instances should preserve the user-assigned identity IDs Azure currently shows on visible container groups",
			))
		} else {
			for _, expectedIdentityID := range truth.IdentityIDs {
				if _, ok := observedIdentityIDs[normalizeResourceID(expectedIdentityID)]; !ok {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-identity-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						fmt.Sprintf("%s surfaced container group id %q with workload_identity_ids %v, but Azure reports %v", label, truth.ID, containerInstanceRowIdentityIDs(row), truth.IdentityIDs),
						"container-instances user-assigned identity rendering or Azure-backed validation context",
						"container-instances should preserve the user-assigned identity IDs Azure currently shows on visible container groups",
					))
					break
				}
			}
		}
	}
	return findings
}

func rowBoolPtr(row map[string]any, key string) *bool {
	value, ok := row[key]
	if !ok || value == nil {
		return nil
	}
	boolValue, ok := value.(bool)
	if !ok {
		return nil
	}
	return &boolValue
}

func rowIntPtr(row map[string]any, key string) *int {
	value, ok := row[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case float64:
		intValue := int(typed)
		return &intValue
	case int:
		intValue := typed
		return &intValue
	default:
		return nil
	}
}

func ValidateLiveRun(runResultsPath, hoAzureDir string) (LiveValidationSummary, error) {
	runResults := RunResult{}
	if err := LoadJSON(runResultsPath, &runResults); err != nil {
		return LiveValidationSummary{}, err
	}
	commandLog := CommandLog{}
	commandLogPath := filepath.Join(filepath.Dir(runResultsPath), "artifacts", "command-log.json")
	if err := LoadJSON(commandLogPath, &commandLog); err != nil {
		return LiveValidationSummary{}, err
	}
	surface, err := DeriveSurface(hoAzureDir)
	if err != nil {
		return LiveValidationSummary{}, err
	}

	findings := []Finding{}
	checkedPayloads := []string{}
	payloadsByViewpoint := map[string]map[string]map[string]any{}
	for _, entry := range commandLog.Entries {
		if entry.Status != "pass" {
			continue
		}
		label := fmt.Sprintf("%s %s (%s)", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint)
		if entry.PayloadPath == "" {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-payload", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				label+" passed but did not record a payload path",
				"lab runner payload recording",
				"successful runs should always record the emitted payload path",
			))
			continue
		}
		payloadPath := filepath.Join(filepath.Dir(runResultsPath), entry.PayloadPath)
		payloadData, err := os.ReadFile(payloadPath)
		if err != nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-payload-file", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				label+" passed but the payload file is missing",
				"lab runner artifact writing",
				"successful runs should leave the referenced payload artifact on disk",
			))
			continue
		}

		payload := map[string]any{}
		if err := json.Unmarshal(payloadData, &payload); err != nil {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-invalid-json", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				label+" emitted payload text that is not valid JSON",
				"tool output rendering or runner payload capture",
				"JSON-mode runs should emit valid JSON payloads",
			))
			continue
		}

		contractName := entry.SurfaceName
		expectedFields := []string{}
		if entry.SurfaceKind == "families" {
			contractName = surface.FamilyGroupCommands[entry.SurfaceName]
			expectedFields = groupedFamilyTopLevelFields(contractName)
		} else {
			expectedFields = surface.CommandTopLevelFields[contractName]
		}
		missingFields := []string{}
		for _, field := range expectedFields {
			if _, ok := payload[field]; !ok {
				missingFields = append(missingFields, field)
			}
		}
		if len(missingFields) > 0 {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-missing-fields", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s is missing contracted top-level fields: %s", label, strings.Join(missingFields, ", ")),
				contractName+" output contract or lab runner capture",
				"live payloads should include every contracted top-level field in JSON mode",
			))
			continue
		}

		if entry.SurfaceKind == "families" {
			groupCommand := surface.FamilyGroupCommands[entry.SurfaceName]
			identityKey := groupedFamilyIdentityKey(groupCommand)
			if identityKey != "" {
				if selected, _ := payload[identityKey].(string); selected != entry.SurfaceName {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-selection-mismatch", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						label+" did not identify itself cleanly in the grouped payload",
						groupCommand+" grouped output selection fields",
						fmt.Sprintf("grouped payloads should set %s to %s", identityKey, entry.SurfaceName),
					))
					continue
				}
			}
		}
		liveContext, err := loadLiveAzureContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		liveInventoryContext, err := loadLiveInventoryContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateWhoAmIPayloadAgainstAzureContext(entry, label, payload, liveContext)...)
		findings = append(findings, validateInventoryPayloadAgainstAzureContext(entry, label, payload, liveInventoryContext)...)
		liveManagedIdentitiesContext, err := loadLiveManagedIdentitiesContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateManagedIdentitiesPayloadAgainstAzureContext(entry, label, payload, liveManagedIdentitiesContext)...)
		liveWorkloadsContext, err := loadLiveWorkloadsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateWorkloadsPayloadAgainstAzureContext(entry, label, payload, liveWorkloadsContext)...)
		liveAppServicesContext, err := loadLiveAppServicesContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateAppServicesPayloadAgainstAzureContext(entry, label, payload, liveAppServicesContext)...)
		liveFunctionsContext, err := loadLiveFunctionsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateFunctionsPayloadAgainstAzureContext(entry, label, payload, liveFunctionsContext)...)
		liveEnvVarsContext, err := loadLiveEnvVarsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateEnvVarsPayloadAgainstAzureContext(entry, label, payload, liveEnvVarsContext)...)
		liveTokensCredentialsContext, err := loadLiveTokensCredentialsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateTokensCredentialsPayloadAgainstAzureContext(entry, label, payload, liveTokensCredentialsContext)...)
		liveAppCredentialsContext, err := loadLiveAppCredentialsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateAppCredentialsPayloadAgainstAzureContext(entry, label, payload, liveAppCredentialsContext)...)
		liveAuthPoliciesContext, err := loadLiveAuthPoliciesContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateAuthPoliciesPayloadAgainstAzureContext(entry, label, payload, liveAuthPoliciesContext)...)
		liveCrossTenantContext, err := loadLiveCrossTenantContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateCrossTenantPayloadAgainstAzureContext(entry, label, payload, liveCrossTenantContext)...)
		liveRoleTrustsContext, err := loadLiveRoleTrustsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateRoleTrustsPayloadAgainstAzureContext(entry, label, payload, liveRoleTrustsContext)...)
		liveArmDeploymentsContext, err := loadLiveArmDeploymentsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateArmDeploymentsPayloadAgainstAzureContext(entry, label, payload, liveArmDeploymentsContext)...)
		liveDNSContext, err := loadLiveDNSContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateDNSPayloadAgainstAzureContext(entry, label, payload, liveDNSContext)...)
		liveEndpointsContext, err := loadLiveEndpointsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateEndpointsPayloadAgainstAzureContext(entry, label, payload, liveEndpointsContext)...)
		liveNetworkEffectiveContext, err := loadLiveNetworkEffectiveContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateNetworkEffectivePayloadAgainstAzureContext(entry, label, payload, liveNetworkEffectiveContext)...)
		liveNetworkPortsContext, err := loadLiveNetworkPortsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateNetworkPortsPayloadAgainstAzureContext(entry, label, payload, liveNetworkPortsContext)...)
		liveContainerAppsContext, err := loadLiveContainerAppsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateContainerAppsPayloadAgainstAzureContext(entry, label, payload, liveContainerAppsContext)...)
		liveContainerInstancesContext, err := loadLiveContainerInstancesContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateContainerInstancesPayloadAgainstAzureContext(entry, label, payload, liveContainerInstancesContext)...)
		liveLogicAppsContext, err := loadLiveLogicAppsContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateLogicAppsPayloadAgainstAzureContext(entry, label, payload, liveLogicAppsContext)...)
		liveAutomationContext, err := loadLiveAutomationContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateAutomationPayloadAgainstAzureContext(entry, label, payload, liveAutomationContext)...)
		liveAzureMLContext, err := loadLiveAzureMLContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateAzureMLPayloadAgainstAzureContext(entry, label, payload, liveAzureMLContext)...)
		liveEventGridContext, err := loadLiveEventGridContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateEventGridPayloadAgainstAzureContext(entry, label, payload, liveEventGridContext)...)
		liveAPIMgmtContext, err := loadLiveAPIMgmtContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateAPIMgmtPayloadAgainstAzureContext(entry, label, payload, liveAPIMgmtContext)...)
		liveApplicationGatewayContext, err := loadLiveApplicationGatewayContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateApplicationGatewayPayloadAgainstAzureContext(entry, label, payload, liveApplicationGatewayContext)...)
		liveDatabasesContext, err := loadLiveDatabasesContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateDatabasesPayloadAgainstAzureContext(entry, label, payload, liveDatabasesContext)...)
		liveKeyVaultContext, err := loadLiveKeyVaultContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateKeyVaultPayloadAgainstAzureContext(entry, label, payload, liveKeyVaultContext)...)
		liveStorageContext, err := loadLiveStorageContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateStoragePayloadAgainstAzureContext(entry, label, payload, liveStorageContext)...)
		findings = append(findings, validateCredentialPathPayloadAgainstAzureContext(entry, label, payload, liveEnvVarsContext, liveTokensCredentialsContext, liveDatabasesContext, liveKeyVaultContext, liveStorageContext)...)
		if entry.SurfaceKind == "families" && entry.SurfaceName == "escalation-path" {
			permissionsPayload, permissionsErr := loadSiblingCommandPayload(payloadPath, "permissions", entry.Viewpoint)
			if permissionsErr != nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-permissions-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					label+" passed but the sibling permissions payload could not be loaded for escalation validation",
					"lab runner sibling source payload capture",
					"targeted escalation-path validation should keep the matching permissions payload available in the same run",
				))
			} else {
				roleTrustsPayload, roleTrustsErr := loadSiblingCommandPayload(payloadPath, "role-trusts", entry.Viewpoint)
				if roleTrustsErr != nil {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-missing-role-trusts-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						label+" passed but the sibling role-trusts payload could not be loaded for escalation validation",
						"lab runner sibling source payload capture",
						"targeted escalation-path validation should keep the matching role-trusts payload available in the same run",
					))
				} else {
					findings = append(findings, validateEscalationPathPayloadAgainstSourceTruth(entry, label, payload, permissionsPayload, roleTrustsPayload)...)
				}
			}
		}
		if entry.SurfaceKind == "families" && entry.SurfaceName == "automation" && payloadGroupedCommandName(payload) == "persistence" {
			automationPayload, automationErr := loadSiblingCommandPayload(payloadPath, "automation", entry.Viewpoint)
			if automationErr != nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-automation-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					label+" passed but the sibling automation payload could not be loaded for persistence validation",
					"lab runner sibling source payload capture",
					"targeted persistence automation validation should keep the matching automation payload available in the same run",
				))
			} else {
				permissionsPayload, permissionsErr := loadSiblingCommandPayload(payloadPath, "permissions", entry.Viewpoint)
				if permissionsErr != nil {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-missing-permissions-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						label+" passed but the sibling permissions payload could not be loaded for persistence validation",
						"lab runner sibling source payload capture",
						"targeted persistence automation validation should keep the matching permissions payload available in the same run",
					))
				} else {
					rbacPayload, rbacErr := loadSiblingCommandPayload(payloadPath, "rbac", entry.Viewpoint)
					if rbacErr != nil {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-missing-rbac-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							label+" passed but the sibling rbac payload could not be loaded for persistence validation",
							"lab runner sibling source payload capture",
							"targeted persistence automation validation should keep the matching rbac payload available in the same run",
						))
					} else {
						findings = append(findings, validatePersistenceAutomationPayloadAgainstSourceTruth(entry, label, payload, automationPayload, permissionsPayload, rbacPayload)...)
					}
				}
			}
		}
		if entry.SurfaceKind == "families" && entry.SurfaceName == "logic-apps" && payloadGroupedCommandName(payload) == "persistence" {
			logicAppsPayload, logicAppsErr := loadSiblingCommandPayload(payloadPath, "logic-apps", entry.Viewpoint)
			if logicAppsErr != nil {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-missing-logic-apps-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
					label+" passed but the sibling logic-apps payload could not be loaded for persistence validation",
					"lab runner sibling source payload capture",
					"targeted persistence logic-apps validation should keep the matching logic-apps payload available in the same run",
				))
			} else {
				permissionsPayload, permissionsErr := loadSiblingCommandPayload(payloadPath, "permissions", entry.Viewpoint)
				if permissionsErr != nil {
					findings = append(findings, makeBlockingFinding(
						fmt.Sprintf("%s-%s-%s-missing-permissions-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
						label+" passed but the sibling permissions payload could not be loaded for persistence validation",
						"lab runner sibling source payload capture",
						"targeted persistence logic-apps validation should keep the matching permissions payload available in the same run",
					))
				} else {
					rbacPayload, rbacErr := loadSiblingCommandPayload(payloadPath, "rbac", entry.Viewpoint)
					if rbacErr != nil {
						findings = append(findings, makeBlockingFinding(
							fmt.Sprintf("%s-%s-%s-missing-rbac-source", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
							label+" passed but the sibling rbac payload could not be loaded for persistence validation",
							"lab runner sibling source payload capture",
							"targeted persistence logic-apps validation should keep the matching rbac payload available in the same run",
						))
					} else {
						findings = append(findings, validatePersistenceLogicAppsPayloadAgainstSourceTruth(entry, label, payload, logicAppsPayload, permissionsPayload, rbacPayload)...)
					}
				}
			}
		}
		liveComputeControlContext, err := loadLiveComputeControlContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateComputeControlPayloadAgainstAzureContext(entry, label, payload, liveComputeControlContext)...)
		findings = append(findings, validateResourceTrustsPayloadAgainstAzureContext(entry, label, payload, liveStorageContext, liveKeyVaultContext)...)
		liveSnapshotsDisksContext, err := loadLiveSnapshotsDisksContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateSnapshotsDisksPayloadAgainstAzureContext(entry, label, payload, liveSnapshotsDisksContext)...)
		liveNICContext, err := loadLiveNICContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateNICsPayloadAgainstAzureContext(entry, label, payload, liveNICContext)...)
		liveVMSContext, err := loadLiveVMSContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateVMSPayloadAgainstAzureContext(entry, label, payload, liveVMSContext)...)
		liveVMSSContext, err := loadLiveVMSSContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateVMSSPayloadAgainstAzureContext(entry, label, payload, liveVMSSContext)...)
		liveACRContext, err := loadLiveACRContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateACRPayloadAgainstAzureContext(entry, label, payload, liveACRContext)...)
		liveAKSContext, err := loadLiveAKSContext(payloadPath)
		if err != nil {
			return LiveValidationSummary{}, err
		}
		findings = append(findings, validateAKSPayloadAgainstAzureContext(entry, label, payload, liveAKSContext)...)
		if entry.SurfaceKind == "commands" {
			if payloadsByViewpoint[entry.Viewpoint] == nil {
				payloadsByViewpoint[entry.Viewpoint] = map[string]map[string]any{}
			}
			payloadsByViewpoint[entry.Viewpoint][entry.SurfaceName] = payload
		}

		checkedPayloads = append(checkedPayloads, label)
	}
	for viewpoint, commandPayloads := range payloadsByViewpoint {
		findings = append(findings, validateWhoAmIPrincipalConsistency(viewpoint, commandPayloads["whoami"], commandPayloads["principals"])...)
		findings = append(findings, validateWhoAmIPermissionsConsistency(viewpoint, commandPayloads["whoami"], commandPayloads["permissions"])...)
		findings = append(findings, validateWhoAmIRbacConsistency(viewpoint, commandPayloads["whoami"], commandPayloads["rbac"])...)
		findings = append(findings, validateWhoAmIPrivescConsistency(viewpoint, commandPayloads["whoami"], commandPayloads["permissions"], commandPayloads["privesc"])...)
	}

	return LiveValidationSummary{
		CheckedPayloadCount: len(checkedPayloads),
		CheckedPayloads:     checkedPayloads,
		FindingCount:        len(findings),
		Findings:            findings,
	}, nil
}
