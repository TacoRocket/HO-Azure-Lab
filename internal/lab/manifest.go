package lab

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
)

var SupportedReasonCodes = []string{
	"manual_setup_not_done",
	"api_gap",
	"cost_not_justified",
	"bootstrap_pending",
	"first_gate_followup",
	"unsupported_surface",
	"explicit_exception",
}

var truthFirstBootstrapCoveredCommands = map[string]struct{}{
	"acr": {}, "aks": {}, "api-mgmt": {}, "app-credentials": {}, "app-services": {}, "application-gateway": {},
	"arm-deployments": {}, "auth-policies": {}, "automation": {}, "azure-ml": {}, "container-apps": {},
	"container-instances": {}, "cross-tenant": {}, "databases": {}, "dns": {}, "endpoints": {}, "env-vars": {},
	"event-grid": {}, "functions": {}, "inventory": {}, "keyvault": {}, "logic-apps": {}, "managed-identities": {},
	"network-effective": {}, "network-ports": {}, "nics": {}, "permissions": {},
	"principals": {}, "privesc": {}, "rbac": {}, "resource-trusts": {}, "role-trusts": {},
	"snapshots-disks": {}, "storage": {}, "tokens-credentials": {}, "vms": {}, "vmss": {},
	"whoami": {}, "workloads": {},
}

type bootstrapManualSurface struct {
	ReasonDetail     string
	ManualSetupSteps []string
}

var truthFirstBootstrapManualCommands = map[string]bootstrapManualSurface{
	"devops": {
		ReasonDetail: "The DevOps canary templates are tracked here, but the standing Azure DevOps org, project, repo, service connection, and variable group path is not wired yet in this lab.",
		ManualSetupSteps: []string{
			"Create or identify the Azure DevOps org, project, and repo for the standing canary lane.",
			"Create the service connection and variable group the canary templates expect.",
			"Record the repeatable setup path in ho-azure-lab-reference before moving devops into the gated run.",
		},
	},
}

var truthFirstBootstrapFollowupCommands = map[string]struct{}{
	"lighthouse": {},
}

var truthFirstBootstrapCoveredFamilies = map[string]struct{}{
	"automation":      {},
	"compute-control": {},
	"credential-path": {},
	"deployment-path": {},
	"escalation-path": {},
	"logic-apps":      {},
}

var truthFirstBootstrapFollowupFamilies = map[string]struct{}{}

func buildSurfaceEntry(defaultStatus, reasonCode string) SurfaceEntry {
	viewpoints := map[string]ViewpointStatus{}
	for _, viewpoint := range []string{"admin", "dev", "lower-privilege"} {
		viewpointEntry := ViewpointStatus{Status: defaultStatus}
		if defaultStatus != "covered" {
			viewpointEntry.ReasonCode = reasonCode
		}
		viewpoints[viewpoint] = viewpointEntry
	}

	entry := SurfaceEntry{
		Status:     defaultStatus,
		Viewpoints: viewpoints,
	}
	if defaultStatus != "covered" {
		entry.ReasonCode = reasonCode
	}
	if reasonCode == "manual_setup_not_done" {
		entry.ManualSetupSteps = []string{
			"Record the manual setup path here before treating this surface as ready.",
		}
	}
	return entry
}

func buildProfiledSurfaceEntry(status, reasonCode, reasonDetail string, manualSetupSteps []string) SurfaceEntry {
	viewpoints := map[string]ViewpointStatus{}
	for _, viewpoint := range []string{"admin", "dev", "lower-privilege"} {
		viewpointEntry := ViewpointStatus{Status: status}
		if status != "covered" {
			viewpointEntry.ReasonCode = reasonCode
			viewpointEntry.ReasonDetail = reasonDetail
		}
		viewpoints[viewpoint] = viewpointEntry
	}

	entry := SurfaceEntry{
		Status:       status,
		ReasonCode:   reasonCode,
		ReasonDetail: reasonDetail,
		Viewpoints:   viewpoints,
	}
	if len(manualSetupSteps) > 0 {
		entry.ManualSetupSteps = manualSetupSteps
	}
	return entry
}

func defaultCompletionContract() CompletionContract {
	return CompletionContract{
		RequireFinalOutcome: true,
		RequireFindings:     true,
		RequireTeardown:     true,
		RequiredArtifacts: []ArtifactRequirement{
			{ID: "command_log", Path: "artifacts/command-log.json", Kind: "log", RequiredWhen: "always"},
			{ID: "command_timeline", Path: "artifacts/command-timeline.json", Kind: "timeline", RequiredWhen: "always"},
			{ID: "demo_capture_index", Path: "artifacts/demo/index.json", Kind: "demo", RequiredWhen: "demo_capture_expected"},
		},
		RequiredReviewTopics: []ReviewTopic{
			{ID: "truthfulness_review", Prompt: "Review truthfulness, omissions, and weaker bounded rows."},
			{ID: "compatibility_review", Prompt: "Review compatibility contracts, negative paths, and benchmark drift."},
			{ID: "cleanup_packaging_review", Prompt: "Review cleanup-readiness, packaging-readiness, and AI-smell findings."},
		},
	}
}

func uniformManifestBase(hoAzureDir string) Manifest {
	resolvedDir, err := filepath.Abs(hoAzureDir)
	if err != nil {
		resolvedDir = hoAzureDir
	}
	return Manifest{
		ManifestVersion: 1,
		Tool: ToolInfo{
			Name:          "HO-Azure",
			RepoPath:      resolvedDir,
			SurfaceSource: filepath.ToSlash("internal/contracts"),
		},
		Viewpoints: map[string]ViewpointDefinition{
			"admin":           {Required: true, Description: "Administrative viewpoint"},
			"dev":             {Required: true, Description: "Developer viewpoint"},
			"lower-privilege": {Required: true, Description: "Lower-privilege viewpoint"},
		},
		Surfaces: SurfaceCatalog{
			Commands: map[string]SurfaceEntry{},
			Families: map[string]SurfaceEntry{},
		},
		Completion: defaultCompletionContract(),
	}
}

func buildTruthFirstBootstrapManifest(hoAzureDir string) (Manifest, error) {
	surface, err := DeriveSurface(hoAzureDir)
	if err != nil {
		return Manifest{}, err
	}

	manifest := uniformManifestBase(hoAzureDir)
	for _, name := range surface.Commands {
		if _, ok := truthFirstBootstrapCoveredCommands[name]; ok {
			manifest.Surfaces.Commands[name] = buildProfiledSurfaceEntry("covered", "", "", nil)
			continue
		}
		if manual, ok := truthFirstBootstrapManualCommands[name]; ok {
			manifest.Surfaces.Commands[name] = buildProfiledSurfaceEntry(
				"excepted",
				"manual_setup_not_done",
				manual.ReasonDetail,
				manual.ManualSetupSteps,
			)
			continue
		}
		if _, ok := truthFirstBootstrapFollowupCommands[name]; ok {
			manifest.Surfaces.Commands[name] = buildProfiledSurfaceEntry(
				"excepted",
				"first_gate_followup",
				"This shipped surface is tracked from day one, but it is not yet admitted into the cohesive first gate for the new lab.",
				nil,
			)
			continue
		}
		return Manifest{}, fmt.Errorf("truth-first-bootstrap profile does not classify shipped command %q", name)
	}

	for _, name := range surface.Families {
		if _, ok := truthFirstBootstrapCoveredFamilies[name]; ok {
			manifest.Surfaces.Families[name] = buildProfiledSurfaceEntry("covered", "", "", nil)
			continue
		}
		if _, ok := truthFirstBootstrapFollowupFamilies[name]; ok {
			manifest.Surfaces.Families[name] = buildProfiledSurfaceEntry(
				"excepted",
				"first_gate_followup",
				"This grouped family is tracked from day one, but it is not yet admitted into the cohesive first gate for the new lab.",
				nil,
			)
			continue
		}
		return Manifest{}, fmt.Errorf("truth-first-bootstrap profile does not classify shipped family %q", name)
	}

	return manifest, nil
}

func ScaffoldManifest(hoAzureDir, defaultStatus, reasonCode, profile string) (Manifest, error) {
	if profile == "truth-first-bootstrap" {
		return buildTruthFirstBootstrapManifest(hoAzureDir)
	}

	if defaultStatus != "covered" && !slices.Contains(SupportedReasonCodes, reasonCode) {
		return Manifest{}, fmt.Errorf("unsupported reason code: %s", reasonCode)
	}

	surface, err := DeriveSurface(hoAzureDir)
	if err != nil {
		return Manifest{}, err
	}
	manifest := uniformManifestBase(hoAzureDir)
	for _, name := range surface.Commands {
		manifest.Surfaces.Commands[name] = buildSurfaceEntry(defaultStatus, reasonCode)
	}
	for _, name := range surface.Families {
		manifest.Surfaces.Families[name] = buildSurfaceEntry(defaultStatus, reasonCode)
	}
	return manifest, nil
}

func RequiredViewpoints(manifest Manifest) []string {
	viewpoints := make([]string, 0, len(manifest.Viewpoints))
	for name, definition := range manifest.Viewpoints {
		if definition.Required {
			viewpoints = append(viewpoints, name)
		}
	}
	sort.Strings(viewpoints)
	return viewpoints
}

func SelectedViewpoints(manifest Manifest, requested string) []string {
	required := RequiredViewpoints(manifest)
	if requested == "all" {
		return required
	}
	return []string{requested}
}

func buildScopeSummary(entries map[string]SurfaceEntry) ScopeSummary {
	summary := ScopeSummary{
		Covered:             []string{},
		ExceptedByReason:    map[string][]string{},
		UnsupportedByReason: map[string][]string{},
	}
	for surfaceName, entry := range entries {
		switch entry.Status {
		case "covered":
			summary.Covered = append(summary.Covered, surfaceName)
		case "excepted":
			reasonCode := entry.ReasonCode
			if reasonCode == "" {
				reasonCode = "unclassified"
			}
			summary.ExceptedByReason[reasonCode] = append(summary.ExceptedByReason[reasonCode], surfaceName)
		default:
			reasonCode := entry.ReasonCode
			if reasonCode == "" {
				reasonCode = "unclassified"
			}
			summary.UnsupportedByReason[reasonCode] = append(summary.UnsupportedByReason[reasonCode], surfaceName)
		}
	}
	sort.Strings(summary.Covered)
	for _, mapping := range []map[string][]string{summary.ExceptedByReason, summary.UnsupportedByReason} {
		for _, names := range mapping {
			sort.Strings(names)
		}
	}
	return summary
}

func summarizeSurfaceEntries(entries map[string]SurfaceEntry) StatusBreakdown {
	breakdown := StatusBreakdown{
		Counts:   map[string]int{"covered": 0, "excepted": 0, "unsupported": 0},
		ByReason: map[string][]string{},
	}
	for name, entry := range entries {
		breakdown.Counts[entry.Status]++
		if entry.ReasonCode != "" {
			breakdown.ByReason[entry.ReasonCode] = append(breakdown.ByReason[entry.ReasonCode], name)
		}
	}
	for _, names := range breakdown.ByReason {
		sort.Strings(names)
	}
	return breakdown
}
