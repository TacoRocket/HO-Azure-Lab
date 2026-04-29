package lab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var viewpointCredentialKeys = map[string]string{
	"dev":             "dev",
	"lower-privilege": "lower_privilege",
}

const defaultAzureCommandTimeout = 10 * time.Minute
const defaultAzureCommandInactivityTimeout = 2 * time.Minute
const defaultAzureSlowCommandThreshold = 3 * time.Minute
const commandProgressHeartbeatInterval = 30 * time.Second

func azureViewpointConfigRoot() string {
	return os.TempDir()
}

func envWithOverrides(overrides ...string) []string {
	replacements := map[string]string{}
	for _, override := range overrides {
		key, _, ok := strings.Cut(override, "=")
		if !ok {
			continue
		}
		replacements[key] = override
	}

	env := make([]string, 0, len(os.Environ())+len(replacements))
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			env = append(env, entry)
			continue
		}
		if _, replace := replacements[key]; replace {
			continue
		}
		env = append(env, entry)
	}
	for _, override := range overrides {
		key, _, ok := strings.Cut(override, "=")
		if !ok {
			env = append(env, override)
			continue
		}
		if replacement, replace := replacements[key]; replace && replacement == override {
			env = append(env, override)
			delete(replacements, key)
		}
	}
	return env
}

func buildSurfaceResults(entries map[string]SurfaceEntry) map[string]map[string]ViewpointResult {
	results := map[string]map[string]ViewpointResult{}
	for surfaceName, entry := range entries {
		viewpointResults := map[string]ViewpointResult{}
		for viewpointName, viewpointEntry := range entry.Viewpoints {
			if viewpointEntry.Status != "covered" {
				continue
			}
			viewpointResults[viewpointName] = ViewpointResult{
				Status: "blocked",
				Notes:  "Replace this placeholder during the real validation run.",
			}
		}
		results[surfaceName] = viewpointResults
	}
	return results
}

func ScaffoldRun(manifest Manifest, outputDir, runID string, demoCaptureExpected bool) (RunResult, error) {
	if err := os.MkdirAll(filepath.Join(outputDir, "artifacts"), 0o755); err != nil {
		return RunResult{}, err
	}

	artifactRecords := map[string]ArtifactRecord{}
	for _, artifact := range manifest.Completion.RequiredArtifacts {
		if artifact.RequiredWhen == "demo_capture_expected" && !demoCaptureExpected {
			continue
		}
		artifactPath := filepath.Join(outputDir, artifact.Path)
		if err := os.MkdirAll(filepath.Dir(artifactPath), 0o755); err != nil {
			return RunResult{}, err
		}
		placeholder := map[string]any{
			"placeholder": true,
			"artifact_id": artifact.ID,
			"notes":       "Replace this placeholder during the real validation run.",
		}
		if err := WriteJSON(artifactPath, placeholder); err != nil {
			return RunResult{}, err
		}
		artifactRecords[artifact.ID] = ArtifactRecord{Path: artifact.Path}
	}

	startedAt := UTCTimestamp()
	return RunResult{
		RunID:               runID,
		StartedAt:           startedAt,
		FinishedAt:          startedAt,
		DemoCaptureExpected: demoCaptureExpected,
		Scope: RunScope{
			RequiredViewpoints: RequiredViewpoints(manifest),
			Commands:           buildScopeSummary(manifest.Surfaces.Commands),
			Families:           buildScopeSummary(manifest.Surfaces.Families),
		},
		SurfaceResults: RunSurfaceResults{
			Commands: buildSurfaceResults(manifest.Surfaces.Commands),
			Families: buildSurfaceResults(manifest.Surfaces.Families),
		},
		Artifacts:    artifactRecords,
		FinalOutcome: "blocked",
		Findings:     []Finding{},
		Teardown: TeardownRecord{
			Status: "standing-resource-recorded",
			Notes:  "Replace this placeholder with teardown verification or standing-resource notes.",
		},
	}, nil
}

func ResolveBaseCommand(hoAzureDir, toolBin string, progressWriter io.Writer) ([]string, string, func(), error) {
	if strings.TrimSpace(toolBin) != "" {
		info, err := os.Stat(toolBin)
		if err != nil {
			return nil, "", nil, fmt.Errorf("tool binary path %q is not usable: %w", toolBin, err)
		}
		if info.IsDir() {
			return nil, "", nil, fmt.Errorf("tool binary path %q is a directory, not a file", toolBin)
		}
		return []string{toolBin}, filepath.Dir(toolBin), nil, nil
	}
	info, err := os.Stat(hoAzureDir)
	if err != nil {
		return nil, "", nil, fmt.Errorf("building a validation binary requires a usable HO-Azure repo path: %w", err)
	}
	if !info.IsDir() {
		return nil, "", nil, fmt.Errorf("HO-Azure repo path %q is not a directory", hoAzureDir)
	}

	buildDir, err := os.MkdirTemp("/tmp", "ho-azure-lab-bin-")
	if err != nil {
		return nil, "", nil, fmt.Errorf("create temp build dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(buildDir)
	}

	binaryPath := filepath.Join(buildDir, "ho-azure")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/azurefox")
	if output, err := runProgressCommand("go build HO-Azure binary (maintainer validation path)", hoAzureDir, os.Environ(), progressWriter, buildCmd); err != nil {
		cleanup()
		return nil, "", nil, fmt.Errorf("go build failed: %s", strings.TrimSpace(string(output)))
	}
	return []string{binaryPath}, buildDir, cleanup, nil
}

func BuildSurfacePlan(manifest Manifest, derived SurfaceSnapshot, viewpoints []string) []SurfaceTask {
	tasks := []SurfaceTask{}
	commandNames := make([]string, 0, len(manifest.Surfaces.Commands))
	for name := range manifest.Surfaces.Commands {
		commandNames = append(commandNames, name)
	}
	slices.Sort(commandNames)
	for _, surfaceName := range commandNames {
		entry := manifest.Surfaces.Commands[surfaceName]
		if entry.Status != "covered" {
			continue
		}
		for _, viewpoint := range viewpoints {
			if entry.Viewpoints[viewpoint].Status != "covered" {
				continue
			}
			tasks = append(tasks, SurfaceTask{
				SurfaceKind:  "commands",
				SurfaceName:  surfaceName,
				Viewpoint:    viewpoint,
				GroupCommand: surfaceName,
			})
		}
	}

	familyNames := make([]string, 0, len(manifest.Surfaces.Families))
	for name := range manifest.Surfaces.Families {
		familyNames = append(familyNames, name)
	}
	slices.Sort(familyNames)
	for _, surfaceName := range familyNames {
		entry := manifest.Surfaces.Families[surfaceName]
		if entry.Status != "covered" {
			continue
		}
		groupCommand := entry.GroupCommand
		if groupCommand == "" {
			groupCommand = derived.FamilyGroupCommands[surfaceName]
		}
		subcommand := entry.Subcommand
		if subcommand == "" {
			subcommand = surfaceName
		}
		for _, viewpoint := range viewpoints {
			if entry.Viewpoints[viewpoint].Status != "covered" {
				continue
			}
			tasks = append(tasks, SurfaceTask{
				SurfaceKind:  "families",
				SurfaceName:  surfaceName,
				Viewpoint:    viewpoint,
				GroupCommand: groupCommand,
				Subcommand:   subcommand,
			})
		}
	}
	return tasks
}

func normalizeRunProfileSelectors(selectors []string) []string {
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, selector := range selectors {
		for _, part := range strings.Split(selector, ",") {
			name := strings.TrimSpace(part)
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			normalized = append(normalized, name)
		}
	}
	sort.Strings(normalized)
	return normalized
}

func LoadRunProfileDefinition(path string) (RunProfileDefinition, error) {
	definition := RunProfileDefinition{}
	if strings.TrimSpace(path) == "" {
		return definition, nil
	}
	if err := LoadJSON(path, &definition); err != nil {
		return RunProfileDefinition{}, err
	}
	return definition, nil
}

func validateRunProfileSelectors(manifest Manifest, commands, families []string) error {
	for _, name := range commands {
		entry, ok := manifest.Surfaces.Commands[name]
		if !ok {
			return fmt.Errorf("selected command %q is not present in the manifest", name)
		}
		if entry.Status != "covered" {
			return fmt.Errorf("selected command %q is %s in the manifest, not covered", name, entry.Status)
		}
	}
	for _, name := range families {
		entry, ok := manifest.Surfaces.Families[name]
		if !ok {
			return fmt.Errorf("selected family %q is not present in the manifest", name)
		}
		if entry.Status != "covered" {
			return fmt.Errorf("selected family %q is %s in the manifest, not covered", name, entry.Status)
		}
	}
	return nil
}

func surfaceTaskKey(task SurfaceTask) string {
	return task.SurfaceKind + "\x00" + task.SurfaceName + "\x00" + task.Viewpoint
}

func taskSelectorMatches(task SurfaceTask, commandSelectors, familySelectors map[string]struct{}, selectorsActive bool) bool {
	if !selectorsActive {
		return true
	}
	if task.SurfaceKind == "commands" {
		_, ok := commandSelectors[task.SurfaceName]
		return ok
	}
	if task.SurfaceKind == "families" {
		_, ok := familySelectors[task.SurfaceName]
		return ok
	}
	return false
}

func runProfileTask(task SurfaceTask) RunProfileTask {
	return RunProfileTask{
		SurfaceKind:  task.SurfaceKind,
		SurfaceName:  task.SurfaceName,
		Viewpoint:    task.Viewpoint,
		GroupCommand: task.GroupCommand,
		Subcommand:   task.Subcommand,
	}
}

func runProfileSkippedTask(manifest Manifest, task SurfaceTask, reason string) RunProfileSkippedTask {
	var entry SurfaceEntry
	if task.SurfaceKind == "commands" {
		entry = manifest.Surfaces.Commands[task.SurfaceName]
	} else {
		entry = manifest.Surfaces.Families[task.SurfaceName]
	}
	viewpointEntry := entry.Viewpoints[task.Viewpoint]
	reasonCode := viewpointEntry.ReasonCode
	if reasonCode == "" {
		reasonCode = entry.ReasonCode
	}
	reasonDetail := viewpointEntry.ReasonDetail
	if reasonDetail == "" {
		reasonDetail = entry.ReasonDetail
	}
	return RunProfileSkippedTask{
		SurfaceKind:     task.SurfaceKind,
		SurfaceName:     task.SurfaceName,
		Viewpoint:       task.Viewpoint,
		Reason:          reason,
		SurfaceStatus:   entry.Status,
		ViewpointStatus: viewpointEntry.Status,
		ReasonCode:      reasonCode,
		ReasonDetail:    reasonDetail,
	}
}

func BuildRunProfile(manifest Manifest, derived SurfaceSnapshot, runID, profile string, selectedViewpoints, commandSelectors, familySelectors []string) (RunProfileArtifact, []SurfaceTask, error) {
	commands := normalizeRunProfileSelectors(commandSelectors)
	families := normalizeRunProfileSelectors(familySelectors)
	if err := validateRunProfileSelectors(manifest, commands, families); err != nil {
		return RunProfileArtifact{}, nil, err
	}

	selectorsActive := len(commands) > 0 || len(families) > 0
	requiredViewpoints := RequiredViewpoints(manifest)
	profileName := strings.TrimSpace(profile)
	if profileName == "" && (selectorsActive || !slices.Equal(selectedViewpoints, requiredViewpoints)) {
		profileName = "selector"
	}
	if profileName == "" {
		profileName = "release-candidate"
	}

	commandSelectorSet := map[string]struct{}{}
	for _, name := range commands {
		commandSelectorSet[name] = struct{}{}
	}
	familySelectorSet := map[string]struct{}{}
	for _, name := range families {
		familySelectorSet[name] = struct{}{}
	}
	selectedViewpointSet := map[string]struct{}{}
	for _, viewpoint := range selectedViewpoints {
		selectedViewpointSet[viewpoint] = struct{}{}
	}

	admittedTasks := BuildSurfacePlan(manifest, derived, requiredViewpoints)
	selectedTasks := []SurfaceTask{}
	selectedKeys := map[string]struct{}{}
	selectedCommandNames := map[string]struct{}{}
	selectedFamilyNames := map[string]struct{}{}
	for _, task := range admittedTasks {
		if _, ok := selectedViewpointSet[task.Viewpoint]; !ok {
			continue
		}
		if !taskSelectorMatches(task, commandSelectorSet, familySelectorSet, selectorsActive) {
			continue
		}
		selectedTasks = append(selectedTasks, task)
		selectedKeys[surfaceTaskKey(task)] = struct{}{}
		if task.SurfaceKind == "commands" {
			selectedCommandNames[task.SurfaceName] = struct{}{}
		}
		if task.SurfaceKind == "families" {
			selectedFamilyNames[task.SurfaceName] = struct{}{}
		}
	}
	for _, name := range commands {
		if _, ok := selectedCommandNames[name]; !ok {
			return RunProfileArtifact{}, nil, fmt.Errorf("selected command %q has no covered viewpoint in this run", name)
		}
	}
	for _, name := range families {
		if _, ok := selectedFamilyNames[name]; !ok {
			return RunProfileArtifact{}, nil, fmt.Errorf("selected family %q has no covered viewpoint in this run", name)
		}
	}

	selectedRecords := make([]RunProfileTask, 0, len(selectedTasks))
	for _, task := range selectedTasks {
		selectedRecords = append(selectedRecords, runProfileTask(task))
	}

	skippedRecords := []RunProfileSkippedTask{}
	for _, task := range admittedTasks {
		if _, ok := selectedKeys[surfaceTaskKey(task)]; ok {
			continue
		}
		reason := "viewpoint_not_selected"
		if _, ok := selectedViewpointSet[task.Viewpoint]; ok && selectorsActive {
			reason = "surface_not_selected"
		}
		skippedRecords = append(skippedRecords, runProfileSkippedTask(manifest, task, reason))
	}

	profileArtifact := RunProfileArtifact{
		RunID:              runID,
		Profile:            profileName,
		RequiredViewpoints: requiredViewpoints,
		SelectedViewpoints: selectedViewpoints,
		Selectors: RunProfileSelectors{
			Commands: commands,
			Families: families,
		},
		SelectedCount: len(selectedRecords),
		SkippedCount:  len(skippedRecords),
		Selected:      selectedRecords,
		Skipped:       skippedRecords,
	}
	return profileArtifact, selectedTasks, nil
}

func WriteRunProfile(outputDir string, profile RunProfileArtifact) error {
	return WriteJSON(filepath.Join(outputDir, "artifacts", "run-profile.json"), profile)
}

func BuildInvocation(baseCommand []string, task SurfaceTask, outdir, tenant, subscription, devopsOrganization, outputFormat string, includeOutdir bool) []string {
	command := append([]string{}, baseCommand...)
	command = append(command, task.GroupCommand)
	if task.Subcommand != "" {
		command = append(command, task.Subcommand)
	}
	if tenant != "" {
		command = append(command, "--tenant", tenant)
	}
	if subscription != "" {
		command = append(command, "--subscription", subscription)
	}
	if devopsOrganization != "" {
		command = append(command, "--devops-organization", devopsOrganization)
	}
	command = append(command, "--output", outputFormat)
	if includeOutdir {
		command = append(command, "--outdir", outdir)
	}
	return command
}

func artifactRelpath(outputDir, target string) string {
	relpath, err := filepath.Rel(outputDir, target)
	if err != nil {
		return target
	}
	return filepath.ToSlash(relpath)
}

func WriteCommandLog(outputDir, runID string, entries []CommandLogEntry) error {
	return WriteJSON(filepath.Join(outputDir, "artifacts", "command-log.json"), CommandLog{
		RunID:      runID,
		EntryCount: len(entries),
		Entries:    entries,
	})
}

func WriteCommandTimeline(outputDir string, runResult RunResult, entries []CommandLogEntry) error {
	return WriteJSON(filepath.Join(outputDir, "artifacts", "command-timeline.json"), CommandTimeline{
		RunID:      runResult.RunID,
		StartedAt:  runResult.StartedAt,
		FinishedAt: runResult.FinishedAt,
		Scope:      runResult.Scope,
		EntryCount: len(entries),
		Entries:    entries,
	})
}

func UpdateRunResultPath(outputDir string, runResult RunResult) error {
	return WriteJSON(filepath.Join(outputDir, "run-result.json"), runResult)
}

func loadViewpointCredentials(path string) (map[string]map[string]string, error) {
	if path == "" {
		return map[string]map[string]string{}, nil
	}
	payload := map[string]map[string]string{}
	if err := LoadJSON(path, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

type liveAzureContextArtifact struct {
	TenantID        string `json:"tenant_id"`
	SubscriptionID  string `json:"subscription_id"`
	PrincipalID     string `json:"principal_id"`
	PrincipalType   string `json:"principal_type"`
	PrincipalName   string `json:"principal_name"`
	AccountUserName string `json:"account_user_name,omitempty"`
	AccountUserType string `json:"account_user_type,omitempty"`
}

type liveManagedIdentitiesContextArtifact struct {
	Identities []liveManagedIdentityTruth `json:"identities"`
}

type liveManagedIdentityTruth struct {
	DisplayName  string   `json:"display_name"`
	PrincipalID  string   `json:"principal_id"`
	IdentityType string   `json:"identity_type"`
	AttachedTo   []string `json:"attached_to"`
}

type liveWorkloadsContextArtifact struct {
	Workloads []liveWorkloadTruth `json:"workloads"`
}

type liveWorkloadTruth struct {
	AssetID      string   `json:"asset_id"`
	AssetKind    string   `json:"asset_kind"`
	AssetName    string   `json:"asset_name"`
	IdentityType string   `json:"identity_type,omitempty"`
	IdentityIDs  []string `json:"identity_ids,omitempty"`
}

type liveAppServicesContextArtifact struct {
	AppServices []liveAppServiceTruth `json:"app_services"`
}

type liveAppServiceTruth struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Hostname            string   `json:"hostname,omitempty"`
	PublicNetworkAccess string   `json:"public_network_access,omitempty"`
	IdentityType        string   `json:"identity_type,omitempty"`
	IdentityIDs         []string `json:"identity_ids,omitempty"`
}

type liveFunctionsContextArtifact struct {
	FunctionApps []liveFunctionTruth `json:"function_apps"`
}

type liveFunctionTruth struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Hostname            string   `json:"hostname,omitempty"`
	PublicNetworkAccess string   `json:"public_network_access,omitempty"`
	IdentityType        string   `json:"identity_type,omitempty"`
	IdentityIDs         []string `json:"identity_ids,omitempty"`
}

type liveDNSContextArtifact struct {
	DNSZones []liveDNSTruth `json:"dns_zones"`
}

type liveDNSTruth struct {
	ID                              string   `json:"id"`
	Name                            string   `json:"name"`
	ResourceGroup                   string   `json:"resource_group,omitempty"`
	Location                        string   `json:"location,omitempty"`
	ZoneKind                        string   `json:"zone_kind,omitempty"`
	RecordSetCount                  *int     `json:"record_set_count,omitempty"`
	MaxRecordSetCount               *int     `json:"max_record_set_count,omitempty"`
	NameServers                     []string `json:"name_servers,omitempty"`
	LinkedVirtualNetworkCount       *int     `json:"linked_virtual_network_count,omitempty"`
	RegistrationVirtualNetworkCount *int     `json:"registration_virtual_network_count,omitempty"`
	PrivateEndpointReferenceCount   *int     `json:"private_endpoint_reference_count,omitempty"`
	RelatedIDs                      []string `json:"related_ids,omitempty"`
}

type liveEndpointsContextArtifact struct {
	Endpoints []liveEndpointTruth `json:"endpoints"`
}

type liveEndpointTruth struct {
	Endpoint        string `json:"endpoint"`
	EndpointType    string `json:"endpoint_type"`
	ExposureFamily  string `json:"exposure_family"`
	IngressPath     string `json:"ingress_path"`
	SourceAssetID   string `json:"source_asset_id"`
	SourceAssetKind string `json:"source_asset_kind"`
	SourceAssetName string `json:"source_asset_name"`
}

type liveNetworkEffectiveContextArtifact struct {
	EffectiveExposures []liveNetworkEffectiveTruth `json:"effective_exposures"`
}

type liveNetworkEffectiveTruth struct {
	AssetID              string   `json:"asset_id"`
	AssetName            string   `json:"asset_name"`
	Endpoint             string   `json:"endpoint"`
	EndpointType         string   `json:"endpoint_type"`
	EffectiveExposure    string   `json:"effective_exposure"`
	InternetExposedPorts []string `json:"internet_exposed_ports,omitempty"`
	ConstrainedPorts     []string `json:"constrained_ports,omitempty"`
	ObservedPaths        []string `json:"observed_paths,omitempty"`
	RelatedIDs           []string `json:"related_ids,omitempty"`
	SummaryBoundary      string   `json:"summary_boundary,omitempty"`
}

type liveNetworkPortsContextArtifact struct {
	NetworkPorts []liveNetworkPortTruth `json:"network_ports"`
}

type liveNetworkPortTruth struct {
	AssetID            string   `json:"asset_id"`
	AssetName          string   `json:"asset_name"`
	Endpoint           string   `json:"endpoint"`
	Protocol           string   `json:"protocol"`
	Port               string   `json:"port"`
	AllowSourceSummary string   `json:"allow_source_summary"`
	ExposureConfidence string   `json:"exposure_confidence"`
	RelatedIDs         []string `json:"related_ids,omitempty"`
}

type liveApplicationGatewayContextArtifact struct {
	ApplicationGateways []liveApplicationGatewayTruth `json:"application_gateways"`
}

type liveApplicationGatewayTruth struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	ResourceGroup           string   `json:"resource_group,omitempty"`
	Location                string   `json:"location,omitempty"`
	State                   string   `json:"state,omitempty"`
	PublicFrontendCount     int      `json:"public_frontend_count,omitempty"`
	PublicIPAddresses       []string `json:"public_ip_addresses,omitempty"`
	ListenerCount           int      `json:"listener_count,omitempty"`
	RequestRoutingRuleCount int      `json:"request_routing_rule_count,omitempty"`
	BackendPoolCount        int      `json:"backend_pool_count,omitempty"`
	BackendTargetCount      int      `json:"backend_target_count,omitempty"`
	FirewallPolicyID        string   `json:"firewall_policy_id,omitempty"`
	RelatedIDs              []string `json:"related_ids,omitempty"`
}

type liveVMSContextArtifact struct {
	VMAssets []liveVMTruth `json:"vm_assets"`
}

type liveAPIMgmtContextArtifact struct {
	Services []liveAPIMgmtTruth `json:"api_management_services"`
}

type liveDatabasesContextArtifact struct {
	DatabaseServers []liveDatabaseServerTruth `json:"database_servers"`
}

type liveVMTruth struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ResourceGroup string   `json:"resource_group,omitempty"`
	Location      string   `json:"location,omitempty"`
	PowerState    string   `json:"power_state,omitempty"`
	PublicIPs     []string `json:"public_ips,omitempty"`
	PrivateIPs    []string `json:"private_ips,omitempty"`
	IdentityIDs   []string `json:"identity_ids,omitempty"`
	NICIDs        []string `json:"nic_ids,omitempty"`
	VMType        string   `json:"vm_type,omitempty"`
}

type liveVMSSContextArtifact struct {
	VMSSAssets []liveVMSSTruth `json:"vmss_assets"`
}

type liveNICContextArtifact struct {
	NICAssets []liveNICTruth `json:"nic_assets"`
}

type liveVMSSTruth struct {
	ID                                 string   `json:"id"`
	Name                               string   `json:"name"`
	ResourceGroup                      string   `json:"resource_group,omitempty"`
	Location                           string   `json:"location,omitempty"`
	SKUName                            string   `json:"sku_name,omitempty"`
	InstanceCount                      *int     `json:"instance_count,omitempty"`
	IdentityType                       string   `json:"identity_type,omitempty"`
	IdentityIDs                        []string `json:"identity_ids,omitempty"`
	NICConfigurationCount              int      `json:"nic_configuration_count,omitempty"`
	PublicIPConfigurationCount         int      `json:"public_ip_configuration_count,omitempty"`
	LoadBalancerBackendPoolCount       int      `json:"load_balancer_backend_pool_count,omitempty"`
	InboundNATPoolCount                int      `json:"inbound_nat_pool_count,omitempty"`
	ApplicationGatewayBackendPoolCount int      `json:"application_gateway_backend_pool_count,omitempty"`
	SubnetIDs                          []string `json:"subnet_ids,omitempty"`
	OrchestrationMode                  string   `json:"orchestration_mode,omitempty"`
	UpgradeMode                        string   `json:"upgrade_mode,omitempty"`
	SinglePlacementGroup               *bool    `json:"single_placement_group,omitempty"`
	Overprovision                      *bool    `json:"overprovision,omitempty"`
}

type liveNICTruth struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	AttachedAssetID        string   `json:"attached_asset_id,omitempty"`
	AttachedAssetName      string   `json:"attached_asset_name,omitempty"`
	NetworkSecurityGroupID string   `json:"network_security_group_id,omitempty"`
	PrivateIPs             []string `json:"private_ips,omitempty"`
	PublicIPIDs            []string `json:"public_ip_ids,omitempty"`
	SubnetIDs              []string `json:"subnet_ids,omitempty"`
	VnetIDs                []string `json:"vnet_ids,omitempty"`
}

type liveAPIMgmtTruth struct {
	ID                           string   `json:"id"`
	Name                         string   `json:"name"`
	ResourceGroup                string   `json:"resource_group,omitempty"`
	Location                     string   `json:"location,omitempty"`
	State                        string   `json:"state,omitempty"`
	SKUName                      string   `json:"sku_name,omitempty"`
	SKUCapacity                  *int     `json:"sku_capacity,omitempty"`
	PublicNetworkAccess          string   `json:"public_network_access,omitempty"`
	VirtualNetworkType           string   `json:"virtual_network_type,omitempty"`
	PublicIPAddressID            string   `json:"public_ip_address_id,omitempty"`
	PublicIPAddresses            []string `json:"public_ip_addresses,omitempty"`
	PrivateIPAddresses           []string `json:"private_ip_addresses,omitempty"`
	GatewayHostnames             []string `json:"gateway_hostnames,omitempty"`
	ManagementHostnames          []string `json:"management_hostnames,omitempty"`
	PortalHostnames              []string `json:"portal_hostnames,omitempty"`
	WorkloadIdentityType         string   `json:"workload_identity_type,omitempty"`
	WorkloadPrincipalID          string   `json:"workload_principal_id,omitempty"`
	WorkloadClientID             string   `json:"workload_client_id,omitempty"`
	WorkloadIdentityIDs          []string `json:"workload_identity_ids,omitempty"`
	GatewayEnabled               *bool    `json:"gateway_enabled,omitempty"`
	DeveloperPortalStatus        string   `json:"developer_portal_status,omitempty"`
	LegacyPortalStatus           string   `json:"legacy_portal_status,omitempty"`
	APICount                     *int     `json:"api_count,omitempty"`
	APISubscriptionRequiredCount *int     `json:"api_subscription_required_count,omitempty"`
	SubscriptionCount            *int     `json:"subscription_count,omitempty"`
	ActiveSubscriptionCount      *int     `json:"active_subscription_count,omitempty"`
	BackendCount                 *int     `json:"backend_count,omitempty"`
	BackendHostnames             []string `json:"backend_hostnames,omitempty"`
	NamedValueCount              *int     `json:"named_value_count,omitempty"`
	NamedValueSecretCount        *int     `json:"named_value_secret_count,omitempty"`
	NamedValueKeyVaultCount      *int     `json:"named_value_key_vault_count,omitempty"`
	RelatedIDs                   []string `json:"related_ids,omitempty"`
}

type liveDatabaseServerTruth struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	ResourceGroup            string   `json:"resource_group,omitempty"`
	Location                 string   `json:"location,omitempty"`
	Engine                   string   `json:"engine,omitempty"`
	FullyQualifiedDomainName string   `json:"fully_qualified_domain_name,omitempty"`
	PublicNetworkAccess      string   `json:"public_network_access,omitempty"`
	MinimalTLSVersion        string   `json:"minimal_tls_version,omitempty"`
	ServerVersion            string   `json:"server_version,omitempty"`
	State                    string   `json:"state,omitempty"`
	DatabaseCount            *int     `json:"database_count,omitempty"`
	UserDatabaseNames        []string `json:"user_database_names,omitempty"`
	WorkloadIdentityType     string   `json:"workload_identity_type,omitempty"`
	WorkloadPrincipalID      string   `json:"workload_principal_id,omitempty"`
	WorkloadClientID         string   `json:"workload_client_id,omitempty"`
	WorkloadIdentityIDs      []string `json:"workload_identity_ids,omitempty"`
	RelatedIDs               []string `json:"related_ids,omitempty"`
}

type liveContainerAppsContextArtifact struct {
	ContainerApps []liveContainerAppTruth `json:"container_apps"`
}

type liveContainerAppTruth struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	DefaultHostname     string   `json:"default_hostname,omitempty"`
	EnvironmentID       string   `json:"environment_id,omitempty"`
	ExternalIngress     *bool    `json:"external_ingress_enabled,omitempty"`
	IngressTargetPort   *int     `json:"ingress_target_port,omitempty"`
	IngressTransport    string   `json:"ingress_transport,omitempty"`
	LatestReadyRevision string   `json:"latest_ready_revision_name,omitempty"`
	LatestRevision      string   `json:"latest_revision_name,omitempty"`
	RevisionMode        string   `json:"revision_mode,omitempty"`
	IdentityType        string   `json:"identity_type,omitempty"`
	IdentityIDs         []string `json:"identity_ids,omitempty"`
}

type liveContainerInstancesContextArtifact struct {
	ContainerInstances []liveContainerInstanceTruth `json:"container_instances"`
}

type liveContainerInstanceTruth struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	PublicIPAddress   string   `json:"public_ip_address,omitempty"`
	FQDN              string   `json:"fqdn,omitempty"`
	ExposedPorts      []int    `json:"exposed_ports,omitempty"`
	RestartPolicy     string   `json:"restart_policy,omitempty"`
	OSType            string   `json:"os_type,omitempty"`
	ProvisioningState string   `json:"provisioning_state,omitempty"`
	ContainerCount    int      `json:"container_count,omitempty"`
	ContainerImages   []string `json:"container_images,omitempty"`
	SubnetIDs         []string `json:"subnet_ids,omitempty"`
	IdentityType      string   `json:"identity_type,omitempty"`
	IdentityIDs       []string `json:"identity_ids,omitempty"`
}

type liveLogicAppsContextArtifact struct {
	Workflows []liveLogicAppTruth `json:"workflows"`
}

type liveLogicAppTruth struct {
	ID                               string   `json:"id"`
	Name                             string   `json:"name"`
	ResourceGroup                    string   `json:"resource_group,omitempty"`
	Location                         string   `json:"location,omitempty"`
	State                            string   `json:"state,omitempty"`
	WorkflowKind                     string   `json:"workflow_kind,omitempty"`
	IdentityType                     string   `json:"identity_type,omitempty"`
	PrincipalID                      string   `json:"principal_id,omitempty"`
	ClientID                         string   `json:"client_id,omitempty"`
	IdentityIDs                      []string `json:"identity_ids,omitempty"`
	TriggerTypes                     []string `json:"trigger_types,omitempty"`
	ExternallyCallableRequestTrigger bool     `json:"externally_callable_request_trigger,omitempty"`
	RecurrenceSummary                string   `json:"recurrence_summary,omitempty"`
	DownstreamActionKinds            []string `json:"downstream_action_kinds,omitempty"`
	Classification                   string   `json:"classification,omitempty"`
}

type liveAutomationContextArtifact struct {
	AutomationAccounts []liveAutomationTruth `json:"automation_accounts"`
}

type liveAutomationTruth struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	ResourceGroup          string   `json:"resource_group,omitempty"`
	Location               string   `json:"location,omitempty"`
	State                  string   `json:"state,omitempty"`
	SKUName                string   `json:"sku_name,omitempty"`
	IdentityType           string   `json:"identity_type,omitempty"`
	PrincipalID            string   `json:"principal_id,omitempty"`
	ClientID               string   `json:"client_id,omitempty"`
	IdentityIDs            []string `json:"identity_ids,omitempty"`
	RunbookCount           *int     `json:"runbook_count,omitempty"`
	PublishedRunbookCount  *int     `json:"published_runbook_count,omitempty"`
	ScheduleCount          *int     `json:"schedule_count,omitempty"`
	JobScheduleCount       *int     `json:"job_schedule_count,omitempty"`
	WebhookCount           *int     `json:"webhook_count,omitempty"`
	HybridWorkerGroupCount *int     `json:"hybrid_worker_group_count,omitempty"`
	CredentialCount        *int     `json:"credential_count,omitempty"`
	CertificateCount       *int     `json:"certificate_count,omitempty"`
	ConnectionCount        *int     `json:"connection_count,omitempty"`
	VariableCount          *int     `json:"variable_count,omitempty"`
	EncryptedVariableCount *int     `json:"encrypted_variable_count,omitempty"`
}

type liveACRContextArtifact struct {
	Registries []liveACRTruth `json:"registries"`
}

type liveACRTruth struct {
	ID                             string   `json:"id"`
	Name                           string   `json:"name"`
	ResourceGroup                  string   `json:"resource_group,omitempty"`
	Location                       string   `json:"location,omitempty"`
	State                          string   `json:"state,omitempty"`
	LoginServer                    string   `json:"login_server,omitempty"`
	SKUName                        string   `json:"sku_name,omitempty"`
	PublicNetworkAccess            string   `json:"public_network_access,omitempty"`
	NetworkRuleDefaultAction       string   `json:"network_rule_default_action,omitempty"`
	NetworkRuleBypassOptions       string   `json:"network_rule_bypass_options,omitempty"`
	AdminUserEnabled               *bool    `json:"admin_user_enabled,omitempty"`
	AnonymousPullEnabled           *bool    `json:"anonymous_pull_enabled,omitempty"`
	DataEndpointEnabled            *bool    `json:"data_endpoint_enabled,omitempty"`
	PrivateEndpointConnectionCount *int     `json:"private_endpoint_connection_count,omitempty"`
	WebhookCount                   *int     `json:"webhook_count,omitempty"`
	EnabledWebhookCount            *int     `json:"enabled_webhook_count,omitempty"`
	WebhookActionTypes             []string `json:"webhook_action_types,omitempty"`
	BroadWebhookScopeCount         *int     `json:"broad_webhook_scope_count,omitempty"`
	ReplicationCount               *int     `json:"replication_count,omitempty"`
	ReplicationRegions             []string `json:"replication_regions,omitempty"`
	QuarantinePolicyStatus         string   `json:"quarantine_policy_status,omitempty"`
	RetentionPolicyStatus          string   `json:"retention_policy_status,omitempty"`
	RetentionPolicyDays            *int     `json:"retention_policy_days,omitempty"`
	TrustPolicyStatus              string   `json:"trust_policy_status,omitempty"`
	TrustPolicyType                string   `json:"trust_policy_type,omitempty"`
	IdentityType                   string   `json:"identity_type,omitempty"`
	WorkloadPrincipalID            string   `json:"workload_principal_id,omitempty"`
	WorkloadClientID               string   `json:"workload_client_id,omitempty"`
	IdentityIDs                    []string `json:"identity_ids,omitempty"`
}

type liveAKSContextArtifact struct {
	AKSClusters []liveAKSTruth `json:"aks_clusters"`
}

type liveAKSTruth struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	ResourceGroup         string   `json:"resource_group,omitempty"`
	Location              string   `json:"location,omitempty"`
	ProvisioningState     string   `json:"provisioning_state,omitempty"`
	KubernetesVersion     string   `json:"kubernetes_version,omitempty"`
	SKUTier               string   `json:"sku_tier,omitempty"`
	NodeResourceGroup     string   `json:"node_resource_group,omitempty"`
	FQDN                  string   `json:"fqdn,omitempty"`
	ClusterIdentityType   string   `json:"cluster_identity_type,omitempty"`
	ClusterPrincipalID    string   `json:"cluster_principal_id,omitempty"`
	ClusterIdentityIDs    []string `json:"cluster_identity_ids,omitempty"`
	LocalAccountsDisabled *bool    `json:"local_accounts_disabled,omitempty"`
	NetworkPlugin         string   `json:"network_plugin,omitempty"`
	NetworkPolicy         string   `json:"network_policy,omitempty"`
	OutboundType          string   `json:"outbound_type,omitempty"`
	AgentPoolCount        *int     `json:"agent_pool_count,omitempty"`
	OIDCIssuerEnabled     *bool    `json:"oidc_issuer_enabled,omitempty"`
	OIDCIssuerURL         string   `json:"oidc_issuer_url,omitempty"`
	AddonNames            []string `json:"addon_names,omitempty"`
}

type azAccountShow struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	User     struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"user"`
}

type azAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
}

type azManagedIdentityShow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	PrincipalID string `json:"principalId"`
}

type azIdentityEnabledResource struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Identity struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
}

type azWorkloadResource struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Kind     string `json:"kind"`
	Identity struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
}

type azAppServiceResource struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	DefaultHostName     string `json:"defaultHostName"`
	PublicNetworkAccess string `json:"publicNetworkAccess"`
	Properties          struct {
		DefaultHostName     string `json:"defaultHostName"`
		PublicNetworkAccess string `json:"publicNetworkAccess"`
	} `json:"properties"`
	Identity struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
}

type azDNSZoneResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Location      string `json:"location"`
	ResourceGroup string `json:"resourceGroup"`
	Properties    struct {
		NumberOfRecordSets                      *int     `json:"numberOfRecordSets"`
		MaxNumberOfRecordSets                   *int     `json:"maxNumberOfRecordSets"`
		NameServers                             []string `json:"nameServers"`
		NumberOfVirtualNetworkLinks             *int     `json:"numberOfVirtualNetworkLinks"`
		NumberOfVirtualNetworkLinksRegistration *int     `json:"numberOfVirtualNetworkLinksWithRegistration"`
	} `json:"properties"`
}

type azVMDetailedResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	PublicIPs     string `json:"publicIps"`
	PrivateIPs    string `json:"privateIps"`
	PowerState    string `json:"powerState"`
}

type azVMShowResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	Identity      struct {
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	NetworkProfile struct {
		NetworkInterfaces []struct {
			ID string `json:"id"`
		} `json:"networkInterfaces"`
	} `json:"networkProfile"`
	Properties struct {
		NetworkProfile struct {
			NetworkInterfaces []struct {
				ID string `json:"id"`
			} `json:"networkInterfaces"`
		} `json:"networkProfile"`
	} `json:"properties"`
}

type azVMSSListResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
}

type azVMSSShowResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	SKU           struct {
		Name     string `json:"name"`
		Capacity *int   `json:"capacity"`
	} `json:"sku"`
	Identity struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	Properties struct {
		OrchestrationMode    string `json:"orchestrationMode"`
		Overprovision        *bool  `json:"overprovision"`
		SinglePlacementGroup *bool  `json:"singlePlacementGroup"`
		UpgradePolicy        struct {
			Mode string `json:"mode"`
		} `json:"upgradePolicy"`
		VirtualMachineProfile struct {
			NetworkProfile struct {
				NetworkInterfaceConfigurations []struct {
					Properties struct {
						IPConfigurations []struct {
							Properties struct {
								PublicIPAddressConfiguration    map[string]any `json:"publicIPAddressConfiguration"`
								Subnet                          *azSubnetRef   `json:"subnet"`
								LoadBalancerBackendAddressPools []struct {
									ID string `json:"id"`
								} `json:"loadBalancerBackendAddressPools"`
								LoadBalancerInboundNatPools []struct {
									ID string `json:"id"`
								} `json:"loadBalancerInboundNatPools"`
								ApplicationGatewayBackendAddressPools []struct {
									ID string `json:"id"`
								} `json:"applicationGatewayBackendAddressPools"`
							} `json:"properties"`
						} `json:"ipConfigurations"`
					} `json:"properties"`
				} `json:"networkInterfaceConfigurations"`
			} `json:"networkProfile"`
		} `json:"virtualMachineProfile"`
	} `json:"properties"`
}

type azSubnetRef struct {
	ID string `json:"id"`
}

type azNICIPConfiguration struct {
	PrivateIPAddress string `json:"privateIPAddress"`
	PublicIPAddress  *struct {
		ID string `json:"id"`
	} `json:"publicIPAddress"`
	Properties struct {
		PrivateIPAddress string `json:"privateIPAddress"`
		PublicIPAddress  *struct {
			ID string `json:"id"`
		} `json:"publicIPAddress"`
		Subnet *azSubnetRef `json:"subnet"`
	} `json:"properties"`
	Subnet *azSubnetRef `json:"subnet"`
}

type azNICResource struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ResourceGroup  string `json:"resourceGroup"`
	VirtualMachine *struct {
		ID string `json:"id"`
	} `json:"virtualMachine"`
	NetworkSecurityGroup *struct {
		ID string `json:"id"`
	} `json:"networkSecurityGroup"`
	IPConfigurations []azNICIPConfiguration `json:"ipConfigurations"`
	Properties       struct {
		VirtualMachine *struct {
			ID string `json:"id"`
		} `json:"virtualMachine"`
		NetworkSecurityGroup *struct {
			ID string `json:"id"`
		} `json:"networkSecurityGroup"`
		IPConfigurations []azNICIPConfiguration `json:"ipConfigurations"`
	} `json:"properties"`
}

type azSubnetResource struct {
	ID                   string `json:"id"`
	NetworkSecurityGroup *struct {
		ID string `json:"id"`
	} `json:"networkSecurityGroup"`
	Properties struct {
		NetworkSecurityGroup *struct {
			ID string `json:"id"`
		} `json:"networkSecurityGroup"`
	} `json:"properties"`
}

type azNSGResource struct {
	ID            string      `json:"id"`
	SecurityRules []azNSGRule `json:"securityRules"`
	Properties    struct {
		SecurityRules []azNSGRule `json:"securityRules"`
	} `json:"properties"`
}

type azNSGRule struct {
	Name                  string   `json:"name"`
	Access                string   `json:"access"`
	Direction             string   `json:"direction"`
	Protocol              string   `json:"protocol"`
	DestinationPortRange  string   `json:"destinationPortRange"`
	DestinationPortRanges []string `json:"destinationPortRanges"`
	SourceAddressPrefix   string   `json:"sourceAddressPrefix"`
	SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
	Properties            struct {
		Access                string   `json:"access"`
		Direction             string   `json:"direction"`
		Protocol              string   `json:"protocol"`
		DestinationPortRange  string   `json:"destinationPortRange"`
		DestinationPortRanges []string `json:"destinationPortRanges"`
		SourceAddressPrefix   string   `json:"sourceAddressPrefix"`
		SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
	} `json:"properties"`
}

type liveNetworkPortEvidence struct {
	AllowSourceSummary string
	ExposureConfidence string
	Port               string
	Protocol           string
	RelatedIDs         []string
}

type liveVMNetworkEvidence struct {
	AssetID    string
	AssetName  string
	Endpoint   string
	RelatedIDs []string
	Evidence   []liveNetworkPortEvidence
}

type azPrivateEndpointResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
}

type azPrivateEndpointDNSZoneConfig struct {
	Properties struct {
		PrivateDNSZoneID string `json:"privateDnsZoneId"`
	} `json:"properties"`
	PrivateDNSZoneID string `json:"privateDnsZoneId"`
}

type azPrivateEndpointDNSZoneGroup struct {
	Properties struct {
		PrivateDNSZoneConfigs []azPrivateEndpointDNSZoneConfig `json:"privateDnsZoneConfigs"`
	} `json:"properties"`
	PrivateDNSZoneConfigs []azPrivateEndpointDNSZoneConfig `json:"privateDnsZoneConfigs"`
}

type azContainerAppResource struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Identity struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	Properties struct {
		ManagedEnvironmentID string `json:"managedEnvironmentId"`
		EnvironmentID        string `json:"environmentId"`
		LatestReadyRevision  string `json:"latestReadyRevisionName"`
		LatestRevision       string `json:"latestRevisionName"`
		Configuration        struct {
			ActiveRevisionsMode string `json:"activeRevisionsMode"`
			Ingress             struct {
				External   *bool  `json:"external"`
				FQDN       string `json:"fqdn"`
				TargetPort *int   `json:"targetPort"`
				Transport  string `json:"transport"`
			} `json:"ingress"`
		} `json:"configuration"`
	} `json:"properties"`
}

type azContainerInstanceResource struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Location          string `json:"location"`
	OSType            string `json:"osType"`
	ProvisioningState string `json:"provisioningState"`
	RestartPolicy     string `json:"restartPolicy"`
	Identity          struct {
		Type                   string         `json:"type"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	IPAddress struct {
		FQDN  string `json:"fqdn"`
		IP    string `json:"ip"`
		Ports []struct {
			Port int `json:"port"`
		} `json:"ports"`
	} `json:"ipAddress"`
	Containers []struct {
		Image string `json:"image"`
	} `json:"containers"`
	SubnetIDs []struct {
		ID string `json:"id"`
	} `json:"subnetIds"`
}

type azAKSResource struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	ResourceGroup     string `json:"resourceGroup"`
	Location          string `json:"location"`
	ProvisioningState string `json:"provisioningState"`
	KubernetesVersion string `json:"kubernetesVersion"`
	NodeResourceGroup string `json:"nodeResourceGroup"`
	FQDN              string `json:"fqdn"`
	Identity          struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	SKU struct {
		Tier string `json:"tier"`
	} `json:"sku"`
	NetworkProfile struct {
		NetworkPlugin string `json:"networkPlugin"`
		NetworkPolicy string `json:"networkPolicy"`
		OutboundType  string `json:"outboundType"`
	} `json:"networkProfile"`
	AgentPoolProfiles []struct {
		Name string `json:"name"`
	} `json:"agentPoolProfiles"`
	OIDCIssuerProfile struct {
		Enabled   *bool  `json:"enabled"`
		IssuerURL string `json:"issuerUrl"`
	} `json:"oidcIssuerProfile"`
	AddonProfiles map[string]struct {
		Enabled bool `json:"enabled"`
	} `json:"addonProfiles"`
	DisableLocalAccounts *bool `json:"disableLocalAccounts"`
}

type azLogicAppResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	Kind          string `json:"kind"`
	Identity      struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		ClientID               string         `json:"clientId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	Properties struct {
		State      string         `json:"state"`
		Definition map[string]any `json:"definition"`
	} `json:"properties"`
}

type azAutomationAccountResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	State         string `json:"state"`
	SKU           struct {
		Name string `json:"name"`
	} `json:"sku"`
	Identity struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		ClientID               string         `json:"clientId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
}

type azAutomationListResponse struct {
	Value []map[string]any `json:"value"`
}

type azApplicationGatewayListResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
}

type azApplicationGatewayShowResource struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ResourceGroup    string `json:"resourceGroup"`
	Location         string `json:"location"`
	OperationalState string `json:"operationalState"`
	FirewallPolicy   struct {
		ID string `json:"id"`
	} `json:"firewallPolicy"`
	FrontendIPConfigurations []struct {
		PublicIPAddress struct {
			ID string `json:"id"`
		} `json:"publicIPAddress"`
	} `json:"frontendIPConfigurations"`
	HTTPListeners []struct {
		ID string `json:"id"`
	} `json:"httpListeners"`
	RequestRoutingRules []struct {
		ID string `json:"id"`
	} `json:"requestRoutingRules"`
	BackendAddressPools []struct {
		BackendAddresses []struct {
			FQDN      string `json:"fqdn"`
			IPAddress string `json:"ipAddress"`
		} `json:"backendAddresses"`
		BackendIPConfigurations []struct {
			ID string `json:"id"`
		} `json:"backendIPConfigurations"`
	} `json:"backendAddressPools"`
}

type azPublicIPResource struct {
	ID        string `json:"id"`
	IPAddress string `json:"ipAddress"`
}

type azACRListResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
}

type azACRShowResource struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	Location                 string `json:"location"`
	ProvisioningState        string `json:"provisioningState"`
	LoginServer              string `json:"loginServer"`
	PublicNetworkAccess      string `json:"publicNetworkAccess"`
	NetworkRuleBypassOptions string `json:"networkRuleBypassOptions"`
	Identity                 struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		ClientID               string         `json:"clientId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	SKU struct {
		Name string `json:"name"`
	} `json:"sku"`
	NetworkRuleSet struct {
		DefaultAction string `json:"defaultAction"`
	} `json:"networkRuleSet"`
	PrivateEndpointConnections []struct {
		ID string `json:"id"`
	} `json:"privateEndpointConnections"`
	AdminUserEnabled     *bool `json:"adminUserEnabled"`
	AnonymousPullEnabled *bool `json:"anonymousPullEnabled"`
	DataEndpointEnabled  *bool `json:"dataEndpointEnabled"`
	Policies             struct {
		QuarantinePolicy struct {
			Status string `json:"status"`
		} `json:"quarantinePolicy"`
		RetentionPolicy struct {
			Status string `json:"status"`
			Days   int    `json:"days"`
		} `json:"retentionPolicy"`
		TrustPolicy struct {
			Status string `json:"status"`
			Type   string `json:"type"`
		} `json:"trustPolicy"`
	} `json:"policies"`
}

type azACRWebhookResource struct {
	ID         string `json:"id"`
	Properties struct {
		Status  string   `json:"status"`
		Actions []string `json:"actions"`
		Scope   string   `json:"scope"`
	} `json:"properties"`
}

type azACRReplicationResource struct {
	ID       string `json:"id"`
	Location string `json:"location"`
}

type azSQLServerListResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
}

type azSQLServerShowResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	Identity      struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		ClientID               string         `json:"clientId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	Properties struct {
		FullyQualifiedDomainName string `json:"fullyQualifiedDomainName"`
		MinimalTLSVersion        string `json:"minimalTlsVersion"`
		PublicNetworkAccess      string `json:"publicNetworkAccess"`
		State                    string `json:"state"`
		Version                  string `json:"version"`
	} `json:"properties"`
}

type azSQLDatabaseListResource struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	ManagedBy string `json:"managedBy"`
}

type azAPIMgmtListResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
}

type azAPIMgmtShowResource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	Identity      struct {
		Type                   string         `json:"type"`
		PrincipalID            string         `json:"principalId"`
		ClientID               string         `json:"clientId"`
		UserAssignedIdentities map[string]any `json:"userAssignedIdentities"`
	} `json:"identity"`
	SKU struct {
		Name     string `json:"name"`
		Capacity *int   `json:"capacity"`
	} `json:"sku"`
	Properties struct {
		ProvisioningState      string   `json:"provisioningState"`
		PublicNetworkAccess    string   `json:"publicNetworkAccess"`
		VirtualNetworkType     string   `json:"virtualNetworkType"`
		PublicIPAddressID      string   `json:"publicIpAddressId"`
		PublicIPAddresses      []string `json:"publicIPAddresses"`
		PrivateIPAddresses     []string `json:"privateIPAddresses"`
		GatewayURL             string   `json:"gatewayUrl"`
		ManagementAPIURL       string   `json:"managementApiUrl"`
		PortalURL              string   `json:"portalUrl"`
		DeveloperPortalURL     string   `json:"developerPortalUrl"`
		DisableGateway         *bool    `json:"disableGateway"`
		DeveloperPortalStatus  string   `json:"developerPortalStatus"`
		LegacyPortalStatus     string   `json:"legacyPortalStatus"`
		HostnameConfigurations []struct {
			HostName string `json:"hostName"`
			Type     string `json:"type"`
		} `json:"hostnameConfigurations"`
	} `json:"properties"`
}

type azAPIMAPIListResponse struct {
	Value []azAPIMAPIResource `json:"value"`
}

type azAPIMAPIResource struct {
	Properties struct {
		SubscriptionRequired *bool `json:"subscriptionRequired"`
	} `json:"properties"`
}

type azAPIMSubscriptionListResponse struct {
	Value []azAPIMSubscriptionResource `json:"value"`
}

type azAPIMSubscriptionResource struct {
	Properties struct {
		State string `json:"state"`
	} `json:"properties"`
}

type azAPIMBackendListResponse struct {
	Value []azAPIMBackendResource `json:"value"`
}

type azAPIMBackendResource struct {
	URL        string `json:"url"`
	Properties struct {
		URL string `json:"url"`
	} `json:"properties"`
}

type azAPIMNamedValueListResponse struct {
	Value []azAPIMNamedValueResource `json:"value"`
}

type azAPIMNamedValueResource struct {
	Properties struct {
		Secret   *bool `json:"secret"`
		KeyVault *struct {
			SecretIdentifier string `json:"secretIdentifier"`
		} `json:"keyVault"`
	} `json:"properties"`
}

func managedIdentitySupportedResourceType(resourceType string) bool {
	switch strings.TrimSpace(resourceType) {
	case "Microsoft.Compute/virtualMachines",
		"Microsoft.Compute/virtualMachineScaleSets",
		"Microsoft.Web/sites",
		"Microsoft.Logic/workflows":
		return true
	default:
		return false
	}
}

func workloadSupportedResourceType(resourceType string) bool {
	switch strings.TrimSpace(resourceType) {
	case "Microsoft.Compute/virtualMachines",
		"Microsoft.Compute/virtualMachineScaleSets",
		"Microsoft.Web/sites",
		"Microsoft.App/containerApps",
		"Microsoft.ContainerInstance/containerGroups":
		return true
	default:
		return false
	}
}

func workloadAssetKind(resourceType, kind string) string {
	switch strings.TrimSpace(resourceType) {
	case "Microsoft.Compute/virtualMachines":
		return "VM"
	case "Microsoft.Compute/virtualMachineScaleSets":
		return "VMSS"
	case "Microsoft.Web/sites":
		if strings.Contains(strings.ToLower(kind), "functionapp") {
			return "FunctionApp"
		}
		return "AppService"
	case "Microsoft.App/containerApps":
		return "ContainerApp"
	case "Microsoft.ContainerInstance/containerGroups":
		return "ContainerInstance"
	default:
		return ""
	}
}

func workloadIdentityIDs(resource azWorkloadResource) []string {
	identityIDs := []string{}
	identityType := strings.ToLower(strings.TrimSpace(resource.Identity.Type))
	if strings.Contains(identityType, "systemassigned") {
		switch strings.TrimSpace(resource.Type) {
		case "Microsoft.Compute/virtualMachines", "Microsoft.Compute/virtualMachineScaleSets":
			identityIDs = append(identityIDs, resource.ID+"/identities/system")
		}
	}
	for identityID := range resource.Identity.UserAssignedIdentities {
		identityIDs = append(identityIDs, identityID)
	}
	sort.Strings(identityIDs)
	return identityIDs
}

func appServiceIdentityIDs(resource azAppServiceResource) []string {
	identityIDs := []string{}
	for identityID := range resource.Identity.UserAssignedIdentities {
		identityIDs = append(identityIDs, identityID)
	}
	sort.Strings(identityIDs)
	return identityIDs
}

func userAssignedIdentityIDs(identityMap map[string]any) []string {
	identityIDs := []string{}
	for identityID := range identityMap {
		identityIDs = append(identityIDs, identityID)
	}
	sort.Strings(identityIDs)
	return identityIDs
}

func resourceGroupFromAzureID(resourceID string) string {
	parts := strings.Split(strings.TrimSpace(resourceID), "/")
	for i := 0; i < len(parts)-1; i++ {
		if !strings.EqualFold(parts[i], "resourceGroups") {
			continue
		}
		return strings.TrimSpace(parts[i+1])
	}
	return ""
}

func normalizeAzureResourceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func vnetIDFromAzureSubnetID(subnetID string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(subnetID), "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if !strings.EqualFold(parts[i], "subnets") {
			continue
		}
		if i < 2 || !strings.EqualFold(parts[i-2], "virtualNetworks") {
			continue
		}
		return "/" + strings.Join(parts[:i], "/")
	}
	return ""
}

func resourceNameFromAzureID(resourceID string) string {
	parts := strings.Split(strings.TrimSpace(resourceID), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if trimmed := strings.TrimSpace(parts[i]); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func azureAuthorizationFailure(output []byte) bool {
	text := strings.ToLower(strings.TrimSpace(string(output)))
	return strings.Contains(text, "authorizationfailed") ||
		strings.Contains(text, "403 forbidden") ||
		strings.Contains(text, "does not have authorization")
}

func decodeJWTPayload(token string) map[string]string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return map[string]string{}
	}

	payload := parts[1]
	if padding := len(payload) % 4; padding != 0 {
		payload += strings.Repeat("=", 4-padding)
	}

	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return map[string]string{}
		}
	}

	decoded := map[string]any{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return map[string]string{}
	}

	claims := map[string]string{}
	for key, value := range decoded {
		switch typed := value.(type) {
		case string:
			claims[key] = typed
		case float64:
			claims[key] = strconv.FormatFloat(typed, 'f', -1, 64)
		case bool:
			claims[key] = strconv.FormatBool(typed)
		}
	}
	return claims
}

func looksLikeUserClaims(claims map[string]string) bool {
	if strings.EqualFold(claims["idtyp"], "app") {
		return false
	}
	return claims["upn"] != "" ||
		claims["preferred_username"] != "" ||
		claims["unique_name"] != "" ||
		claims["scp"] != ""
}

func principalTypeFromClaims(claims map[string]string) string {
	if claims["xms_mirid"] != "" {
		return "ManagedIdentity"
	}
	if looksLikeUserClaims(claims) {
		return "User"
	}
	if strings.EqualFold(claims["idtyp"], "app") || claims["appid"] != "" {
		return "ServicePrincipal"
	}
	if claims["oid"] != "" {
		return "User"
	}
	return "Unknown"
}

func currentPrincipalFromClaims(claims map[string]string) (string, string) {
	principalID := firstNonEmpty(claims["oid"], claims["sub"])
	displayName := firstNonEmpty(
		claims["name"],
		claims["preferred_username"],
		claims["upn"],
		claims["unique_name"],
		claims["azp_name"],
		claims["appid"],
		principalID,
	)
	return principalID, displayName
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func applicationGatewayBackendTargetCountFromAzure(backendPools []struct {
	BackendAddresses []struct {
		FQDN      string `json:"fqdn"`
		IPAddress string `json:"ipAddress"`
	} `json:"backendAddresses"`
	BackendIPConfigurations []struct {
		ID string `json:"id"`
	} `json:"backendIPConfigurations"`
}) int {
	targets := []string{}
	for _, pool := range backendPools {
		for _, address := range pool.BackendAddresses {
			if fqdn := strings.TrimSpace(address.FQDN); fqdn != "" {
				targets = append(targets, "fqdn:"+fqdn)
				continue
			}
			if ip := strings.TrimSpace(address.IPAddress); ip != "" {
				targets = append(targets, "ip:"+ip)
			}
		}
		for _, config := range pool.BackendIPConfigurations {
			if id := strings.TrimSpace(config.ID); id != "" {
				targets = append(targets, "id:"+id)
			}
		}
	}
	sort.Strings(targets)
	return len(slices.Compact(targets))
}

func azureSQLServerIDFromDatabaseID(databaseID string) string {
	trimmed := strings.TrimSpace(databaseID)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	index := strings.Index(lower, "/databases/")
	if index == -1 {
		return ""
	}
	return trimmed[:index]
}

func visibleAzureSQLUserDatabaseNames(databases []azSQLDatabaseListResource, serverID string) []string {
	names := []string{}
	normalizedServerID := normalizeAzureResourceID(serverID)
	for _, database := range databases {
		parentID := normalizeAzureResourceID(firstNonEmptyString(database.ManagedBy, azureSQLServerIDFromDatabaseID(database.ID)))
		if normalizedServerID == "" || parentID != normalizedServerID {
			continue
		}
		if strings.Contains(strings.ToLower(strings.TrimSpace(database.Kind)), "system") {
			continue
		}
		name := resourceNameFromAzureID(database.ID)
		if name == "" {
			name = resourceNameFromAzureID(database.Name)
		}
		if strings.EqualFold(name, "master") || strings.TrimSpace(name) == "" {
			continue
		}
		names = append(names, name)
	}
	return compactSortedStrings(names)
}

func hostnameFromAzureURL(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return strings.TrimSpace(value)
}

func apiMgmtHostnamesByTypeFromAzure(configurations []struct {
	HostName string `json:"hostName"`
	Type     string `json:"type"`
}, types ...string) []string {
	allowedTypes := map[string]struct{}{}
	for _, value := range types {
		allowedTypes[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	hostnames := []string{}
	for _, configuration := range configurations {
		if _, ok := allowedTypes[strings.ToLower(strings.TrimSpace(configuration.Type))]; !ok {
			continue
		}
		hostnames = append(hostnames, configuration.HostName)
	}
	return compactSortedStrings(hostnames)
}

func apiMgmtHostnamesFromAzure(service azAPIMgmtShowResource) ([]string, []string, []string) {
	gatewayHostnames := compactSortedStrings(append(
		apiMgmtHostnamesByTypeFromAzure(service.Properties.HostnameConfigurations, "proxy"),
		hostnameFromAzureURL(service.Properties.GatewayURL),
	))
	managementHostnames := compactSortedStrings(append(
		apiMgmtHostnamesByTypeFromAzure(service.Properties.HostnameConfigurations, "management"),
		hostnameFromAzureURL(service.Properties.ManagementAPIURL),
	))
	portalHostnames := compactSortedStrings(append(
		append(
			apiMgmtHostnamesByTypeFromAzure(service.Properties.HostnameConfigurations, "portal", "developerportal"),
			hostnameFromAzureURL(service.Properties.PortalURL),
		),
		hostnameFromAzureURL(service.Properties.DeveloperPortalURL),
	))
	return gatewayHostnames, managementHostnames, portalHostnames
}

func apiMgmtSubscriptionRequiredCountFromAzure(apis []azAPIMAPIResource) *int {
	count := 0
	for _, api := range apis {
		if api.Properties.SubscriptionRequired != nil && *api.Properties.SubscriptionRequired {
			count++
		}
	}
	return intValuePtr(count)
}

func apiMgmtActiveSubscriptionCountFromAzure(subscriptions []azAPIMSubscriptionResource) *int {
	count := 0
	for _, subscription := range subscriptions {
		if strings.EqualFold(strings.TrimSpace(subscription.Properties.State), "active") {
			count++
		}
	}
	return intValuePtr(count)
}

func apiMgmtBackendHostnamesFromAzure(backends []azAPIMBackendResource) []string {
	hostnames := []string{}
	for _, backend := range backends {
		hostnames = append(hostnames, hostnameFromAzureURL(firstNonEmptyString(strings.TrimSpace(backend.URL), strings.TrimSpace(backend.Properties.URL))))
	}
	return compactSortedStrings(hostnames)
}

func apiMgmtNamedValueSecretCountFromAzure(namedValues []azAPIMNamedValueResource) *int {
	count := 0
	for _, namedValue := range namedValues {
		if namedValue.Properties.Secret != nil && *namedValue.Properties.Secret {
			count++
		}
	}
	return intValuePtr(count)
}

func apiMgmtNamedValueKeyVaultCountFromAzure(namedValues []azAPIMNamedValueResource) *int {
	count := 0
	for _, namedValue := range namedValues {
		if namedValue.Properties.KeyVault != nil && strings.TrimSpace(namedValue.Properties.KeyVault.SecretIdentifier) != "" {
			count++
		}
	}
	return intValuePtr(count)
}

func normalizeAzureVMPowerState(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "vm ")
	return normalized
}

func captureLiveAPIMgmtContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.ApiManagement/service", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (api-mgmt validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for api management services: %s", strings.TrimSpace(string(listOutput)))
	}
	services := []azAPIMgmtListResource{}
	if err := json.Unmarshal(listOutput, &services); err != nil {
		return fmt.Errorf("parse api management service list output: %w", err)
	}

	if len(services) == 0 {
		artifact := liveAPIMgmtContextArtifact{Services: []liveAPIMgmtTruth{}}
		if err := WriteJSON(filepath.Join(outdir, "live-api-mgmt-context.json"), artifact); err != nil {
			return fmt.Errorf("write live api-mgmt context artifact: %w", err)
		}
		return nil
	}

	truths := make([]liveAPIMgmtTruth, 0, len(services))
	for _, listed := range services {
		serviceID := strings.TrimSpace(listed.ID)
		if serviceID == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", serviceID, "--api-version", "2024-05-01", "--output", "json")
		showOutput, err := runProgressCommand("az resource show (api-mgmt validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", serviceID, strings.TrimSpace(string(showOutput)))
		}
		service := azAPIMgmtShowResource{}
		if err := json.Unmarshal(showOutput, &service); err != nil {
			return fmt.Errorf("parse api management service show output for %s: %w", serviceID, err)
		}

		resourceGroup := firstNonEmptyString(strings.TrimSpace(service.ResourceGroup), strings.TrimSpace(listed.ResourceGroup), resourceGroupFromAzureID(serviceID))
		serviceName := firstNonEmptyString(strings.TrimSpace(service.Name), strings.TrimSpace(listed.Name), resourceNameFromAzureID(serviceID))
		baseURL := fmt.Sprintf("https://management.azure.com%s", strings.TrimSpace(serviceID))
		apis := []azAPIMAPIResource{}
		subscriptions := []azAPIMSubscriptionResource{}
		backends := []azAPIMBackendResource{}
		namedValues := []azAPIMNamedValueResource{}

		if resourceGroup != "" && serviceName != "" {
			apiListCmd := exec.Command("az", "rest", "--method", "get", "--url", baseURL+"/apis?api-version=2024-05-01", "--output", "json")
			apiListOutput, err := runProgressCommand("az rest (api-mgmt apis validation context)", workingDir, env, progressWriter, apiListCmd)
			if err != nil {
				return fmt.Errorf("az rest failed for api-mgmt apis on %s: %s", serviceID, strings.TrimSpace(string(apiListOutput)))
			}
			apiResponse := azAPIMAPIListResponse{}
			if err := json.Unmarshal(apiListOutput, &apiResponse); err != nil {
				return fmt.Errorf("parse api-mgmt apis response for %s: %w", serviceID, err)
			}
			apis = apiResponse.Value

			subscriptionListCmd := exec.Command("az", "rest", "--method", "get", "--url", baseURL+"/subscriptions?api-version=2024-05-01", "--output", "json")
			subscriptionListOutput, err := runProgressCommand("az rest (api-mgmt subscriptions validation context)", workingDir, env, progressWriter, subscriptionListCmd)
			if err != nil {
				return fmt.Errorf("az rest failed for api-mgmt subscriptions on %s: %s", serviceID, strings.TrimSpace(string(subscriptionListOutput)))
			}
			subscriptionResponse := azAPIMSubscriptionListResponse{}
			if err := json.Unmarshal(subscriptionListOutput, &subscriptionResponse); err != nil {
				return fmt.Errorf("parse api-mgmt subscriptions response for %s: %w", serviceID, err)
			}
			subscriptions = subscriptionResponse.Value

			backendListCmd := exec.Command("az", "rest", "--method", "get", "--url", baseURL+"/backends?api-version=2024-05-01", "--output", "json")
			backendListOutput, err := runProgressCommand("az rest (api-mgmt backends validation context)", workingDir, env, progressWriter, backendListCmd)
			if err != nil {
				return fmt.Errorf("az rest failed for api-mgmt backends on %s: %s", serviceID, strings.TrimSpace(string(backendListOutput)))
			}
			backendResponse := azAPIMBackendListResponse{}
			if err := json.Unmarshal(backendListOutput, &backendResponse); err != nil {
				return fmt.Errorf("parse api-mgmt backends response for %s: %w", serviceID, err)
			}
			backends = backendResponse.Value

			namedValueListCmd := exec.Command("az", "rest", "--method", "get", "--url", baseURL+"/namedValues?api-version=2024-05-01", "--output", "json")
			namedValueListOutput, err := runProgressCommand("az rest (api-mgmt named-values validation context)", workingDir, env, progressWriter, namedValueListCmd)
			if err != nil {
				return fmt.Errorf("az rest failed for api-mgmt named values on %s: %s", serviceID, strings.TrimSpace(string(namedValueListOutput)))
			}
			namedValueResponse := azAPIMNamedValueListResponse{}
			if err := json.Unmarshal(namedValueListOutput, &namedValueResponse); err != nil {
				return fmt.Errorf("parse api-mgmt named values response for %s: %w", serviceID, err)
			}
			namedValues = namedValueResponse.Value
		}

		gatewayHostnames, managementHostnames, portalHostnames := apiMgmtHostnamesFromAzure(service)
		workloadIdentityIDs := userAssignedIdentityIDs(service.Identity.UserAssignedIdentities)
		relatedIDs := append([]string{serviceID}, workloadIdentityIDs...)
		if principalID := strings.TrimSpace(service.Identity.PrincipalID); principalID != "" {
			relatedIDs = append(relatedIDs, principalID)
		}
		if publicIPAddressID := strings.TrimSpace(service.Properties.PublicIPAddressID); publicIPAddressID != "" {
			relatedIDs = append(relatedIDs, publicIPAddressID)
		}

		gatewayEnabled := (*bool)(nil)
		if service.Properties.DisableGateway != nil {
			enabled := !*service.Properties.DisableGateway
			gatewayEnabled = &enabled
		}

		truths = append(truths, liveAPIMgmtTruth{
			ID:                           serviceID,
			Name:                         serviceName,
			ResourceGroup:                resourceGroup,
			Location:                     firstNonEmptyString(strings.TrimSpace(service.Location), strings.TrimSpace(listed.Location)),
			State:                        strings.TrimSpace(service.Properties.ProvisioningState),
			SKUName:                      strings.TrimSpace(service.SKU.Name),
			SKUCapacity:                  service.SKU.Capacity,
			PublicNetworkAccess:          strings.TrimSpace(service.Properties.PublicNetworkAccess),
			VirtualNetworkType:           strings.TrimSpace(service.Properties.VirtualNetworkType),
			PublicIPAddressID:            strings.TrimSpace(service.Properties.PublicIPAddressID),
			PublicIPAddresses:            compactSortedStrings(service.Properties.PublicIPAddresses),
			PrivateIPAddresses:           compactSortedStrings(service.Properties.PrivateIPAddresses),
			GatewayHostnames:             gatewayHostnames,
			ManagementHostnames:          managementHostnames,
			PortalHostnames:              portalHostnames,
			WorkloadIdentityType:         strings.TrimSpace(service.Identity.Type),
			WorkloadPrincipalID:          strings.TrimSpace(service.Identity.PrincipalID),
			WorkloadClientID:             strings.TrimSpace(service.Identity.ClientID),
			WorkloadIdentityIDs:          workloadIdentityIDs,
			GatewayEnabled:               gatewayEnabled,
			DeveloperPortalStatus:        strings.TrimSpace(service.Properties.DeveloperPortalStatus),
			LegacyPortalStatus:           strings.TrimSpace(service.Properties.LegacyPortalStatus),
			APICount:                     intValuePtr(len(apis)),
			APISubscriptionRequiredCount: apiMgmtSubscriptionRequiredCountFromAzure(apis),
			SubscriptionCount:            intValuePtr(len(subscriptions)),
			ActiveSubscriptionCount:      apiMgmtActiveSubscriptionCountFromAzure(subscriptions),
			BackendCount:                 intValuePtr(len(backends)),
			BackendHostnames:             apiMgmtBackendHostnamesFromAzure(backends),
			NamedValueCount:              intValuePtr(len(namedValues)),
			NamedValueSecretCount:        apiMgmtNamedValueSecretCountFromAzure(namedValues),
			NamedValueKeyVaultCount:      apiMgmtNamedValueKeyVaultCountFromAzure(namedValues),
			RelatedIDs:                   compactSortedStrings(relatedIDs),
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveAPIMgmtContextArtifact{Services: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-api-mgmt-context.json"), artifact); err != nil {
		return fmt.Errorf("write live api-mgmt context artifact: %w", err)
	}
	return nil
}

func captureLiveDatabasesContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Sql/servers", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (databases validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for sql servers: %s", strings.TrimSpace(string(listOutput)))
	}
	servers := []azSQLServerListResource{}
	if err := json.Unmarshal(listOutput, &servers); err != nil {
		return fmt.Errorf("parse sql server list output: %w", err)
	}

	if len(servers) == 0 {
		artifact := liveDatabasesContextArtifact{DatabaseServers: []liveDatabaseServerTruth{}}
		if err := WriteJSON(filepath.Join(outdir, "live-databases-context.json"), artifact); err != nil {
			return fmt.Errorf("write live databases context artifact: %w", err)
		}
		return nil
	}

	databasesCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Sql/servers/databases", "--output", "json")
	databasesOutput, err := runProgressCommand("az resource list (databases child-resource validation context)", workingDir, env, progressWriter, databasesCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed for sql databases: %s", strings.TrimSpace(string(databasesOutput)))
	}
	databases := []azSQLDatabaseListResource{}
	if err := json.Unmarshal(databasesOutput, &databases); err != nil {
		return fmt.Errorf("parse sql database list output: %w", err)
	}

	truths := make([]liveDatabaseServerTruth, 0, len(servers))
	for _, listed := range servers {
		serverID := strings.TrimSpace(listed.ID)
		if serverID == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", serverID, "--api-version", "2023-08-01-preview", "--output", "json")
		showOutput, err := runProgressCommand("az resource show (databases validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", serverID, strings.TrimSpace(string(showOutput)))
		}
		server := azSQLServerShowResource{}
		if err := json.Unmarshal(showOutput, &server); err != nil {
			return fmt.Errorf("parse sql server show output for %s: %w", serverID, err)
		}

		userDatabaseNames := visibleAzureSQLUserDatabaseNames(databases, serverID)
		databaseCount := len(userDatabaseNames)
		workloadIdentityIDs := userAssignedIdentityIDs(server.Identity.UserAssignedIdentities)
		relatedIDs := append([]string{serverID}, workloadIdentityIDs...)
		if principalID := strings.TrimSpace(server.Identity.PrincipalID); principalID != "" {
			relatedIDs = append(relatedIDs, principalID)
		}

		truths = append(truths, liveDatabaseServerTruth{
			ID:                       serverID,
			Name:                     firstNonEmptyString(strings.TrimSpace(server.Name), strings.TrimSpace(listed.Name), resourceNameFromAzureID(serverID), "unknown"),
			ResourceGroup:            firstNonEmptyString(strings.TrimSpace(server.ResourceGroup), strings.TrimSpace(listed.ResourceGroup), resourceGroupFromAzureID(serverID)),
			Location:                 firstNonEmptyString(strings.TrimSpace(server.Location), strings.TrimSpace(listed.Location)),
			Engine:                   "AzureSql",
			FullyQualifiedDomainName: strings.TrimSpace(server.Properties.FullyQualifiedDomainName),
			PublicNetworkAccess:      strings.TrimSpace(server.Properties.PublicNetworkAccess),
			MinimalTLSVersion:        strings.TrimSpace(server.Properties.MinimalTLSVersion),
			ServerVersion:            strings.TrimSpace(server.Properties.Version),
			State:                    strings.TrimSpace(server.Properties.State),
			DatabaseCount:            intValuePtr(databaseCount),
			UserDatabaseNames:        userDatabaseNames,
			WorkloadIdentityType:     strings.TrimSpace(server.Identity.Type),
			WorkloadPrincipalID:      strings.TrimSpace(server.Identity.PrincipalID),
			WorkloadClientID:         strings.TrimSpace(server.Identity.ClientID),
			WorkloadIdentityIDs:      workloadIdentityIDs,
			RelatedIDs:               compactSortedStrings(relatedIDs),
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveDatabasesContextArtifact{DatabaseServers: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-databases-context.json"), artifact); err != nil {
		return fmt.Errorf("write live databases context artifact: %w", err)
	}
	return nil
}

func captureLiveNICContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "network", "nic", "list", "--output", "json")
	listOutput, err := runProgressCommand("az network nic list (nics validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az network nic list failed: %s", strings.TrimSpace(string(listOutput)))
	}
	nics := []azNICResource{}
	if err := json.Unmarshal(listOutput, &nics); err != nil {
		return fmt.Errorf("parse az network nic list output: %w", err)
	}

	truths := make([]liveNICTruth, 0, len(nics))
	for _, nic := range nics {
		nicID := strings.TrimSpace(nic.ID)
		if nicID == "" {
			continue
		}

		attachedAssetID := ""
		if nic.VirtualMachine != nil {
			attachedAssetID = strings.TrimSpace(nic.VirtualMachine.ID)
		}
		if attachedAssetID == "" && nic.Properties.VirtualMachine != nil {
			attachedAssetID = strings.TrimSpace(nic.Properties.VirtualMachine.ID)
		}

		networkSecurityGroupID := ""
		if nic.NetworkSecurityGroup != nil {
			networkSecurityGroupID = strings.TrimSpace(nic.NetworkSecurityGroup.ID)
		}
		if networkSecurityGroupID == "" && nic.Properties.NetworkSecurityGroup != nil {
			networkSecurityGroupID = strings.TrimSpace(nic.Properties.NetworkSecurityGroup.ID)
		}

		privateIPs := []string{}
		publicIPIDs := []string{}
		subnetIDs := []string{}
		vnetIDs := []string{}
		ipConfigurations := nic.IPConfigurations
		if len(ipConfigurations) == 0 {
			ipConfigurations = nic.Properties.IPConfigurations
		}
		for _, ipConfiguration := range ipConfigurations {
			properties := ipConfiguration.Properties
			privateIP := firstNonEmptyString(strings.TrimSpace(ipConfiguration.PrivateIPAddress), strings.TrimSpace(properties.PrivateIPAddress))
			if privateIP != "" {
				privateIPs = append(privateIPs, privateIP)
			}
			publicIPID := ""
			if ipConfiguration.PublicIPAddress != nil {
				publicIPID = strings.TrimSpace(ipConfiguration.PublicIPAddress.ID)
			}
			if publicIPID == "" && properties.PublicIPAddress != nil {
				publicIPID = strings.TrimSpace(properties.PublicIPAddress.ID)
			}
			if publicIPID != "" {
				publicIPIDs = append(publicIPIDs, publicIPID)
			}
			subnetID := ""
			if properties.Subnet != nil {
				subnetID = strings.TrimSpace(properties.Subnet.ID)
			}
			if subnetID == "" && ipConfiguration.Subnet != nil {
				subnetID = strings.TrimSpace(ipConfiguration.Subnet.ID)
			}
			if subnetID != "" {
				subnetIDs = append(subnetIDs, subnetID)
				if vnetID := vnetIDFromAzureSubnetID(subnetID); vnetID != "" {
					vnetIDs = append(vnetIDs, vnetID)
				}
			}
		}

		truths = append(truths, liveNICTruth{
			ID:                     nicID,
			Name:                   firstNonEmptyString(strings.TrimSpace(nic.Name), resourceNameFromAzureID(nicID), "unknown"),
			AttachedAssetID:        attachedAssetID,
			AttachedAssetName:      resourceNameFromAzureID(attachedAssetID),
			NetworkSecurityGroupID: networkSecurityGroupID,
			PrivateIPs:             compactSortedStrings(privateIPs),
			PublicIPIDs:            compactSortedStrings(publicIPIDs),
			SubnetIDs:              compactSortedStrings(subnetIDs),
			VnetIDs:                compactSortedStrings(vnetIDs),
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveNICContextArtifact{NICAssets: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-nics-context.json"), artifact); err != nil {
		return fmt.Errorf("write live nics context artifact: %w", err)
	}
	return nil
}

func captureLiveVMSContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "vm", "list", "-d", "--output", "json")
	listOutput, err := runProgressCommand("az vm list -d (vms validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az vm list -d failed: %s", strings.TrimSpace(string(listOutput)))
	}
	vms := []azVMDetailedResource{}
	if err := json.Unmarshal(listOutput, &vms); err != nil {
		return fmt.Errorf("parse az vm list -d output: %w", err)
	}

	truths := make([]liveVMTruth, 0, len(vms))
	for _, listed := range vms {
		vmID := strings.TrimSpace(listed.ID)
		if vmID == "" {
			continue
		}

		showCmd := exec.Command("az", "vm", "show", "--ids", vmID, "--output", "json")
		showOutput, err := runProgressCommand("az vm show (vms validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az vm show failed for %s: %s", vmID, strings.TrimSpace(string(showOutput)))
		}
		vm := azVMShowResource{}
		if err := json.Unmarshal(showOutput, &vm); err != nil {
			return fmt.Errorf("parse az vm show output for %s: %w", vmID, err)
		}

		nicRefs := vm.NetworkProfile.NetworkInterfaces
		if len(nicRefs) == 0 {
			nicRefs = vm.Properties.NetworkProfile.NetworkInterfaces
		}
		nicIDs := make([]string, 0, len(nicRefs))
		for _, nicRef := range nicRefs {
			if nicID := strings.TrimSpace(nicRef.ID); nicID != "" {
				nicIDs = append(nicIDs, nicID)
			}
		}

		truths = append(truths, liveVMTruth{
			ID:            vmID,
			Name:          firstNonEmptyString(strings.TrimSpace(vm.Name), strings.TrimSpace(listed.Name)),
			ResourceGroup: firstNonEmptyString(strings.TrimSpace(vm.ResourceGroup), strings.TrimSpace(listed.ResourceGroup), resourceGroupFromAzureID(vmID)),
			Location:      strings.TrimSpace(vm.Location),
			PowerState:    normalizeAzureVMPowerState(listed.PowerState),
			PublicIPs:     compactSortedStrings(splitAzureCSVField(listed.PublicIPs)),
			PrivateIPs:    compactSortedStrings(splitAzureCSVField(listed.PrivateIPs)),
			IdentityIDs:   userAssignedIdentityIDs(vm.Identity.UserAssignedIdentities),
			NICIDs:        compactSortedStrings(nicIDs),
			VMType:        "vm",
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveVMSContextArtifact{VMAssets: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-vms-context.json"), artifact); err != nil {
		return fmt.Errorf("write live vms context artifact: %w", err)
	}
	return nil
}

func captureLiveVMSSContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "resource", "list", "--resource-type", "Microsoft.Compute/virtualMachineScaleSets", "--output", "json")
	listOutput, err := runProgressCommand("az resource list (vmss validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az resource list failed: %s", strings.TrimSpace(string(listOutput)))
	}
	scaleSets := []azVMSSListResource{}
	if err := json.Unmarshal(listOutput, &scaleSets); err != nil {
		return fmt.Errorf("parse az resource list output for vmss: %w", err)
	}

	truths := make([]liveVMSSTruth, 0, len(scaleSets))
	for _, listed := range scaleSets {
		vmssID := strings.TrimSpace(listed.ID)
		if vmssID == "" {
			continue
		}

		showCmd := exec.Command("az", "resource", "show", "--ids", vmssID, "--api-version", "2024-11-01", "--output", "json")
		showOutput, err := runProgressCommand("az resource show (vmss validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az resource show failed for %s: %s", vmssID, strings.TrimSpace(string(showOutput)))
		}
		vmss := azVMSSShowResource{}
		if err := json.Unmarshal(showOutput, &vmss); err != nil {
			return fmt.Errorf("parse az resource show output for %s: %w", vmssID, err)
		}

		identityIDs := []string{}
		if strings.TrimSpace(vmss.Identity.PrincipalID) != "" {
			identityIDs = append(identityIDs, vmssID+"/identities/system")
		}
		identityIDs = append(identityIDs, userAssignedIdentityIDs(vmss.Identity.UserAssignedIdentities)...)

		subnetIDs := []string{}
		loadBalancerBackendPoolIDs := []string{}
		inboundNATPoolIDs := []string{}
		applicationGatewayBackendPoolIDs := []string{}
		nicConfigs := vmss.Properties.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations
		publicIPConfigurationCount := 0
		for _, nicConfig := range nicConfigs {
			for _, ipConfig := range nicConfig.Properties.IPConfigurations {
				if len(ipConfig.Properties.PublicIPAddressConfiguration) > 0 {
					publicIPConfigurationCount++
				}
				if ipConfig.Properties.Subnet != nil {
					if subnetID := strings.TrimSpace(ipConfig.Properties.Subnet.ID); subnetID != "" {
						subnetIDs = append(subnetIDs, subnetID)
					}
				}
				for _, pool := range ipConfig.Properties.LoadBalancerBackendAddressPools {
					if poolID := strings.TrimSpace(pool.ID); poolID != "" {
						loadBalancerBackendPoolIDs = append(loadBalancerBackendPoolIDs, poolID)
					}
				}
				for _, pool := range ipConfig.Properties.LoadBalancerInboundNatPools {
					if poolID := strings.TrimSpace(pool.ID); poolID != "" {
						inboundNATPoolIDs = append(inboundNATPoolIDs, poolID)
					}
				}
				for _, pool := range ipConfig.Properties.ApplicationGatewayBackendAddressPools {
					if poolID := strings.TrimSpace(pool.ID); poolID != "" {
						applicationGatewayBackendPoolIDs = append(applicationGatewayBackendPoolIDs, poolID)
					}
				}
			}
		}

		var instanceCount *int
		if vmss.SKU.Capacity != nil {
			instanceCount = intValuePtr(*vmss.SKU.Capacity)
		}

		truths = append(truths, liveVMSSTruth{
			ID:                                 vmssID,
			Name:                               firstNonEmptyString(strings.TrimSpace(vmss.Name), strings.TrimSpace(listed.Name)),
			ResourceGroup:                      firstNonEmptyString(strings.TrimSpace(vmss.ResourceGroup), strings.TrimSpace(listed.ResourceGroup), resourceGroupFromAzureID(vmssID)),
			Location:                           firstNonEmptyString(strings.TrimSpace(vmss.Location), strings.TrimSpace(listed.Location)),
			SKUName:                            strings.TrimSpace(vmss.SKU.Name),
			InstanceCount:                      instanceCount,
			IdentityType:                       strings.TrimSpace(vmss.Identity.Type),
			IdentityIDs:                        compactSortedStrings(identityIDs),
			NICConfigurationCount:              len(nicConfigs),
			PublicIPConfigurationCount:         publicIPConfigurationCount,
			LoadBalancerBackendPoolCount:       len(compactSortedStrings(loadBalancerBackendPoolIDs)),
			InboundNATPoolCount:                len(compactSortedStrings(inboundNATPoolIDs)),
			ApplicationGatewayBackendPoolCount: len(compactSortedStrings(applicationGatewayBackendPoolIDs)),
			SubnetIDs:                          compactSortedStrings(subnetIDs),
			OrchestrationMode:                  strings.TrimSpace(vmss.Properties.OrchestrationMode),
			UpgradeMode:                        strings.TrimSpace(vmss.Properties.UpgradePolicy.Mode),
			SinglePlacementGroup:               vmss.Properties.SinglePlacementGroup,
			Overprovision:                      vmss.Properties.Overprovision,
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveVMSSContextArtifact{VMSSAssets: truths}
	if err := WriteJSON(filepath.Join(outdir, "live-vmss-context.json"), artifact); err != nil {
		return fmt.Errorf("write live vmss context artifact: %w", err)
	}
	return nil
}

func captureLiveApplicationGatewayContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "network", "application-gateway", "list", "--output", "json")
	listOutput, err := runProgressCommand("az network application-gateway list (application-gateway validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az network application-gateway list failed: %s", strings.TrimSpace(string(listOutput)))
	}
	gateways := []azApplicationGatewayListResource{}
	if err := json.Unmarshal(listOutput, &gateways); err != nil {
		return fmt.Errorf("parse az network application-gateway list output: %w", err)
	}

	truths := make([]liveApplicationGatewayTruth, 0, len(gateways))
	for _, listed := range gateways {
		resourceGroup := strings.TrimSpace(listed.ResourceGroup)
		if resourceGroup == "" {
			resourceGroup = resourceGroupFromAzureID(listed.ID)
		}
		gatewayName := strings.TrimSpace(listed.Name)
		if resourceGroup == "" || gatewayName == "" {
			continue
		}

		showCmd := exec.Command("az", "network", "application-gateway", "show", "--resource-group", resourceGroup, "--name", gatewayName, "--output", "json")
		showOutput, err := runProgressCommand("az network application-gateway show (application-gateway validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az network application-gateway show failed for %s/%s: %s", resourceGroup, gatewayName, strings.TrimSpace(string(showOutput)))
		}
		gateway := azApplicationGatewayShowResource{}
		if err := json.Unmarshal(showOutput, &gateway); err != nil {
			return fmt.Errorf("parse az network application-gateway show output for %s/%s: %w", resourceGroup, gatewayName, err)
		}

		publicIPIDs := []string{}
		publicIPAddresses := []string{}
		for _, frontend := range gateway.FrontendIPConfigurations {
			publicIPID := strings.TrimSpace(frontend.PublicIPAddress.ID)
			if publicIPID == "" {
				continue
			}
			publicIPIDs = append(publicIPIDs, publicIPID)

			pipCmd := exec.Command("az", "network", "public-ip", "show", "--ids", publicIPID, "--output", "json")
			pipOutput, err := runProgressCommand("az network public-ip show (application-gateway validation context)", workingDir, env, progressWriter, pipCmd)
			if err != nil {
				return fmt.Errorf("az network public-ip show failed for %s: %s", publicIPID, strings.TrimSpace(string(pipOutput)))
			}
			publicIP := azPublicIPResource{}
			if err := json.Unmarshal(pipOutput, &publicIP); err != nil {
				return fmt.Errorf("parse az network public-ip show output for %s: %w", publicIPID, err)
			}
			if ip := strings.TrimSpace(publicIP.IPAddress); ip != "" {
				publicIPAddresses = append(publicIPAddresses, ip)
			}
		}

		publicIPIDs = slices.Compact(publicIPIDs)
		sort.Strings(publicIPIDs)
		publicIPAddresses = slices.Compact(publicIPAddresses)
		sort.Strings(publicIPAddresses)

		firewallPolicyID := strings.TrimSpace(gateway.FirewallPolicy.ID)
		relatedIDs := []string{strings.TrimSpace(gateway.ID)}
		relatedIDs = append(relatedIDs, publicIPIDs...)
		if firewallPolicyID != "" {
			relatedIDs = append(relatedIDs, firewallPolicyID)
		}
		sort.Strings(relatedIDs)
		relatedIDs = slices.Compact(relatedIDs)

		truths = append(truths, liveApplicationGatewayTruth{
			ID:                      strings.TrimSpace(gateway.ID),
			Name:                    firstNonEmptyString(strings.TrimSpace(gateway.Name), gatewayName),
			ResourceGroup:           firstNonEmptyString(strings.TrimSpace(gateway.ResourceGroup), resourceGroup),
			Location:                strings.TrimSpace(gateway.Location),
			State:                   strings.TrimSpace(gateway.OperationalState),
			PublicFrontendCount:     len(publicIPIDs),
			PublicIPAddresses:       publicIPAddresses,
			ListenerCount:           len(gateway.HTTPListeners),
			RequestRoutingRuleCount: len(gateway.RequestRoutingRules),
			BackendPoolCount:        len(gateway.BackendAddressPools),
			BackendTargetCount:      applicationGatewayBackendTargetCountFromAzure(gateway.BackendAddressPools),
			FirewallPolicyID:        firewallPolicyID,
			RelatedIDs:              relatedIDs,
		})
	}

	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveApplicationGatewayContextArtifact{
		ApplicationGateways: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-application-gateway-context.json"), artifact); err != nil {
		return fmt.Errorf("write live application-gateway context artifact: %w", err)
	}
	return nil
}

func captureLiveACRContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	listCmd := exec.Command("az", "acr", "list", "--output", "json")
	listOutput, err := runProgressCommand("az acr list (acr validation context)", workingDir, env, progressWriter, listCmd)
	if err != nil {
		return fmt.Errorf("az acr list failed: %s", strings.TrimSpace(string(listOutput)))
	}
	registries := []azACRListResource{}
	if err := json.Unmarshal(listOutput, &registries); err != nil {
		return fmt.Errorf("parse az acr list output: %w", err)
	}

	truths := []liveACRTruth{}
	for _, listed := range registries {
		resourceGroup := strings.TrimSpace(listed.ResourceGroup)
		if resourceGroup == "" {
			resourceGroup = resourceGroupFromAzureID(listed.ID)
		}
		registryName := strings.TrimSpace(listed.Name)
		if resourceGroup == "" || registryName == "" {
			continue
		}

		showCmd := exec.Command("az", "acr", "show", "--resource-group", resourceGroup, "--name", registryName, "--output", "json")
		showOutput, err := runProgressCommand("az acr show (acr validation context)", workingDir, env, progressWriter, showCmd)
		if err != nil {
			return fmt.Errorf("az acr show failed for %s/%s: %s", resourceGroup, registryName, strings.TrimSpace(string(showOutput)))
		}
		registry := azACRShowResource{}
		if err := json.Unmarshal(showOutput, &registry); err != nil {
			return fmt.Errorf("parse az acr show output for %s/%s: %w", resourceGroup, registryName, err)
		}

		webhookCmd := exec.Command("az", "acr", "webhook", "list", "--resource-group", resourceGroup, "--registry", registryName, "--output", "json")
		webhookOutput, err := runProgressCommand("az acr webhook list (acr validation context)", workingDir, env, progressWriter, webhookCmd)
		if err != nil {
			return fmt.Errorf("az acr webhook list failed for %s/%s: %s", resourceGroup, registryName, strings.TrimSpace(string(webhookOutput)))
		}
		webhooks := []azACRWebhookResource{}
		if err := json.Unmarshal(webhookOutput, &webhooks); err != nil {
			return fmt.Errorf("parse az acr webhook list output for %s/%s: %w", resourceGroup, registryName, err)
		}

		replications := []azACRReplicationResource{}
		if strings.EqualFold(strings.TrimSpace(registry.SKU.Name), "Premium") {
			replicationCmd := exec.Command("az", "acr", "replication", "list", "--resource-group", resourceGroup, "--registry", registryName, "--output", "json")
			replicationOutput, err := runProgressCommand("az acr replication list (acr validation context)", workingDir, env, progressWriter, replicationCmd)
			if err != nil {
				return fmt.Errorf("az acr replication list failed for %s/%s: %s", resourceGroup, registryName, strings.TrimSpace(string(replicationOutput)))
			}
			if err := json.Unmarshal(replicationOutput, &replications); err != nil {
				return fmt.Errorf("parse az acr replication list output for %s/%s: %w", resourceGroup, registryName, err)
			}
		}

		privateEndpointConnectionCount := len(registry.PrivateEndpointConnections)
		webhookCount := len(webhooks)
		enabledWebhookCount := 0
		broadWebhookScopeCount := 0
		for _, webhook := range webhooks {
			if strings.EqualFold(strings.TrimSpace(webhook.Properties.Status), "enabled") {
				enabledWebhookCount++
			}
			scope := strings.TrimSpace(webhook.Properties.Scope)
			if scope == "" || strings.Contains(scope, "*") {
				broadWebhookScopeCount++
			}
		}
		replicationCount := len(replications)

		var retentionPolicyDays *int
		if strings.TrimSpace(registry.Policies.RetentionPolicy.Status) != "" || registry.Policies.RetentionPolicy.Days != 0 {
			days := registry.Policies.RetentionPolicy.Days
			retentionPolicyDays = &days
		}

		truths = append(truths, liveACRTruth{
			ID:                             strings.TrimSpace(registry.ID),
			Name:                           strings.TrimSpace(registry.Name),
			ResourceGroup:                  resourceGroup,
			Location:                       strings.TrimSpace(registry.Location),
			State:                          strings.TrimSpace(registry.ProvisioningState),
			LoginServer:                    strings.TrimSpace(registry.LoginServer),
			SKUName:                        strings.TrimSpace(registry.SKU.Name),
			PublicNetworkAccess:            strings.TrimSpace(registry.PublicNetworkAccess),
			NetworkRuleDefaultAction:       strings.TrimSpace(registry.NetworkRuleSet.DefaultAction),
			NetworkRuleBypassOptions:       strings.TrimSpace(registry.NetworkRuleBypassOptions),
			AdminUserEnabled:               registry.AdminUserEnabled,
			AnonymousPullEnabled:           registry.AnonymousPullEnabled,
			DataEndpointEnabled:            registry.DataEndpointEnabled,
			PrivateEndpointConnectionCount: &privateEndpointConnectionCount,
			WebhookCount:                   &webhookCount,
			EnabledWebhookCount:            &enabledWebhookCount,
			WebhookActionTypes:             acrWebhookActionTypes(webhooks),
			BroadWebhookScopeCount:         &broadWebhookScopeCount,
			ReplicationCount:               &replicationCount,
			ReplicationRegions:             acrReplicationRegions(replications),
			QuarantinePolicyStatus:         strings.ToLower(strings.TrimSpace(registry.Policies.QuarantinePolicy.Status)),
			RetentionPolicyStatus:          strings.ToLower(strings.TrimSpace(registry.Policies.RetentionPolicy.Status)),
			RetentionPolicyDays:            retentionPolicyDays,
			TrustPolicyStatus:              strings.ToLower(strings.TrimSpace(registry.Policies.TrustPolicy.Status)),
			TrustPolicyType:                strings.ToLower(strings.TrimSpace(registry.Policies.TrustPolicy.Type)),
			IdentityType:                   strings.TrimSpace(registry.Identity.Type),
			WorkloadPrincipalID:            strings.TrimSpace(registry.Identity.PrincipalID),
			WorkloadClientID:               strings.TrimSpace(registry.Identity.ClientID),
			IdentityIDs:                    userAssignedIdentityIDs(registry.Identity.UserAssignedIdentities),
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveACRContextArtifact{
		Registries: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-acr-context.json"), artifact); err != nil {
		return fmt.Errorf("write live acr context artifact: %w", err)
	}
	return nil
}

func acrWebhookActionTypes(webhooks []azACRWebhookResource) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, webhook := range webhooks {
		for _, action := range webhook.Properties.Actions {
			normalized := strings.ToLower(strings.TrimSpace(action))
			if normalized == "" {
				continue
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			values = append(values, normalized)
		}
	}
	sort.Strings(values)
	return values
}

func acrReplicationRegions(replications []azACRReplicationResource) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, replication := range replications {
		region := strings.TrimSpace(replication.Location)
		if region == "" {
			continue
		}
		if _, exists := seen[region]; exists {
			continue
		}
		seen[region] = struct{}{}
		values = append(values, region)
	}
	sort.Strings(values)
	return values
}

func captureLiveAKSContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	resourceCmd := exec.Command("az", "aks", "list", "--output", "json")
	resourceOutput, err := runProgressCommand("az aks list (aks validation context)", workingDir, env, progressWriter, resourceCmd)
	if err != nil {
		return fmt.Errorf("az aks list failed: %s", strings.TrimSpace(string(resourceOutput)))
	}
	resources := []azAKSResource{}
	if err := json.Unmarshal(resourceOutput, &resources); err != nil {
		return fmt.Errorf("parse az aks list output: %w", err)
	}

	truths := []liveAKSTruth{}
	for _, resource := range resources {
		addonNames := []string{}
		for addonName, addon := range resource.AddonProfiles {
			if !addon.Enabled {
				continue
			}
			addonNames = append(addonNames, addonName)
		}
		sort.Strings(addonNames)

		var agentPoolCount *int
		if resource.AgentPoolProfiles != nil {
			count := len(resource.AgentPoolProfiles)
			agentPoolCount = &count
		}

		truths = append(truths, liveAKSTruth{
			ID:                    resource.ID,
			Name:                  resource.Name,
			ResourceGroup:         strings.TrimSpace(resource.ResourceGroup),
			Location:              strings.TrimSpace(resource.Location),
			ProvisioningState:     strings.TrimSpace(resource.ProvisioningState),
			KubernetesVersion:     strings.TrimSpace(resource.KubernetesVersion),
			SKUTier:               strings.TrimSpace(resource.SKU.Tier),
			NodeResourceGroup:     strings.TrimSpace(resource.NodeResourceGroup),
			FQDN:                  strings.TrimSpace(resource.FQDN),
			ClusterIdentityType:   strings.TrimSpace(resource.Identity.Type),
			ClusterPrincipalID:    strings.TrimSpace(resource.Identity.PrincipalID),
			ClusterIdentityIDs:    userAssignedIdentityIDs(resource.Identity.UserAssignedIdentities),
			LocalAccountsDisabled: resource.DisableLocalAccounts,
			NetworkPlugin:         strings.TrimSpace(resource.NetworkProfile.NetworkPlugin),
			NetworkPolicy:         strings.TrimSpace(resource.NetworkProfile.NetworkPolicy),
			OutboundType:          strings.TrimSpace(resource.NetworkProfile.OutboundType),
			AgentPoolCount:        agentPoolCount,
			OIDCIssuerEnabled:     resource.OIDCIssuerProfile.Enabled,
			OIDCIssuerURL:         strings.TrimSpace(resource.OIDCIssuerProfile.IssuerURL),
			AddonNames:            addonNames,
		})
	}
	sort.SliceStable(truths, func(i, j int) bool {
		return truths[i].ID < truths[j].ID
	})

	artifact := liveAKSContextArtifact{
		AKSClusters: truths,
	}
	if err := WriteJSON(filepath.Join(outdir, "live-aks-context.json"), artifact); err != nil {
		return fmt.Errorf("write live aks context artifact: %w", err)
	}
	return nil
}

func runProgressCommand(label, workingDir string, env []string, progressWriter io.Writer, command *exec.Cmd) ([]byte, error) {
	started := time.Now()
	tracker := newActivityTracker(started)
	var output bytes.Buffer
	command.Dir = workingDir
	command.Env = env
	command.Stdout = &activityWriter{tracker: tracker, target: &output}
	command.Stderr = &activityWriter{tracker: tracker, target: &output}

	emitProgress(progressWriter, "[start] %s", label)
	if err := command.Start(); err != nil {
		emitProgress(progressWriter, "[done] %s -> status=fail duration=%.0fs", label, time.Since(started).Seconds())
		return output.Bytes(), err
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- command.Wait()
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	lastHeartbeat := started

	var err error
waitLoop:
	for {
		select {
		case err = <-waitCh:
			break waitLoop
		case <-ticker.C:
			if time.Since(lastHeartbeat) >= commandProgressHeartbeatInterval {
				emitProgress(progressWriter, "[wait] %s still running (%.0fs elapsed)", label, time.Since(started).Seconds())
				lastHeartbeat = time.Now()
			}
		}
	}

	status := "pass"
	if err != nil {
		status = "fail"
	}
	emitProgress(progressWriter, "[done] %s -> status=%s duration=%.0fs", label, status, time.Since(started).Seconds())
	return output.Bytes(), err
}

func setupViewpointSession(viewpoint string, credentials map[string]string, fallbackTenant, fallbackSubscription, workingDir string, progressWriter io.Writer) (string, []string, string, string, error) {
	clientID := strings.TrimSpace(credentials["client_id"])
	clientSecret := strings.TrimSpace(credentials["client_secret"])
	tenantID := strings.TrimSpace(credentials["tenant_id"])
	if tenantID == "" {
		tenantID = fallbackTenant
	}
	subscriptionID := strings.TrimSpace(credentials["subscription_id"])
	if subscriptionID == "" {
		subscriptionID = fallbackSubscription
	}

	if clientID == "" {
		return "", nil, "", "", fmt.Errorf("%s viewpoint is missing a usable client_id", viewpoint)
	}
	if clientSecret == "" {
		return "", nil, "", "", fmt.Errorf("%s viewpoint is missing a usable client_secret", viewpoint)
	}
	if tenantID == "" {
		return "", nil, "", "", fmt.Errorf("%s viewpoint is missing a usable tenant_id", viewpoint)
	}
	if subscriptionID == "" {
		return "", nil, "", "", fmt.Errorf("%s viewpoint is missing a usable subscription_id", viewpoint)
	}

	configDir, err := os.MkdirTemp(azureViewpointConfigRoot(), "ho-azure-"+viewpoint+"-")
	if err != nil {
		return "", nil, "", "", err
	}
	env := envWithOverrides("AZURE_CONFIG_DIR=" + configDir)

	login := exec.Command("az", "login", "--service-principal", "--username", clientID, "--password", clientSecret, "--tenant", tenantID, "--allow-no-subscriptions")
	if output, err := runProgressCommand(fmt.Sprintf("az login (%s viewpoint)", viewpoint), workingDir, env, progressWriter, login); err != nil {
		return "", nil, "", "", fmt.Errorf("az login failed: %s", strings.TrimSpace(string(output)))
	}

	accountSet := exec.Command("az", "account", "set", "--subscription", subscriptionID)
	if output, err := runProgressCommand(fmt.Sprintf("az account set (%s viewpoint)", viewpoint), workingDir, env, progressWriter, accountSet); err != nil {
		return "", nil, "", "", fmt.Errorf("az account set failed: %s", strings.TrimSpace(string(output)))
	}

	return configDir, env, tenantID, subscriptionID, nil
}

func setupAdminAmbientSession(fallbackTenant, fallbackSubscription, workingDir string, progressWriter io.Writer) (string, []string, string, string, error) {
	sourceConfigDir, err := ambientAzureConfigDir()
	if err != nil {
		return "", nil, "", "", err
	}

	configDir, err := os.MkdirTemp(azureViewpointConfigRoot(), "ho-azure-admin-")
	if err != nil {
		return "", nil, "", "", err
	}
	if err := copyDirContents(sourceConfigDir, configDir); err != nil {
		return "", nil, "", "", fmt.Errorf("copy admin Azure CLI config: %w", err)
	}

	env := envWithOverrides("AZURE_CONFIG_DIR=" + configDir)
	accountShow := exec.Command("az", "account", "show", "--output", "json")
	accountShowOutput, err := runProgressCommand("az account show (admin viewpoint)", workingDir, env, progressWriter, accountShow)
	if err != nil {
		return "", nil, "", "", fmt.Errorf("az account show failed: %s", strings.TrimSpace(string(accountShowOutput)))
	}

	account := azAccountShow{}
	if err := json.Unmarshal(accountShowOutput, &account); err != nil {
		return "", nil, "", "", fmt.Errorf("parse az account show output: %w", err)
	}

	tenantID := strings.TrimSpace(fallbackTenant)
	if tenantID == "" {
		tenantID = strings.TrimSpace(account.TenantID)
	}
	subscriptionID := strings.TrimSpace(fallbackSubscription)
	if subscriptionID == "" {
		subscriptionID = strings.TrimSpace(account.ID)
	}
	if subscriptionID == "" {
		return "", nil, "", "", fmt.Errorf("admin viewpoint is missing a usable subscription_id")
	}

	accountSet := exec.Command("az", "account", "set", "--subscription", subscriptionID)
	if output, err := runProgressCommand("az account set (admin viewpoint)", workingDir, env, progressWriter, accountSet); err != nil {
		return "", nil, "", "", fmt.Errorf("az account set failed: %s", strings.TrimSpace(string(output)))
	}

	return configDir, env, tenantID, subscriptionID, nil
}

func ambientAzureConfigDir() (string, error) {
	configDir := strings.TrimSpace(os.Getenv("AZURE_CONFIG_DIR"))
	if configDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve admin Azure CLI config dir: %w", err)
		}
		configDir = filepath.Join(homeDir, ".azure")
	}

	info, err := os.Stat(configDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("admin viewpoint needs an active Azure CLI config at %q", configDir)
		}
		return "", fmt.Errorf("inspect admin Azure CLI config dir %q: %w", configDir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("admin viewpoint Azure CLI config path %q is not a directory", configDir)
	}

	return configDir, nil
}

func copyDirContents(sourceDir, targetDir string) error {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		sourcePath := filepath.Join(sourceDir, entry.Name())
		targetPath := filepath.Join(targetDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}

		if entry.IsDir() {
			if err := os.MkdirAll(targetPath, info.Mode()); err != nil {
				return err
			}
			if err := copyDirContents(sourcePath, targetPath); err != nil {
				return err
			}
			continue
		}

		if err := copyFile(sourcePath, targetPath, info.Mode()); err != nil {
			return err
		}
	}

	return nil
}

func copyFile(sourcePath, targetPath string, mode os.FileMode) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer target.Close()

	if _, err := io.Copy(target, source); err != nil {
		return err
	}
	return nil
}

type AzureRunConfig struct {
	ManifestPath             string
	OutputDir                string
	HOAzureDir               string
	InfraDir                 string
	ToolBin                  string
	TofuBinary               string
	RunID                    string
	RunProfile               string
	CommandSelectors         []string
	FamilySelectors          []string
	Viewpoint                string
	ViewpointCredentials     string
	Tenant                   string
	Subscription             string
	DevOpsOrganization       string
	CommandTimeout           time.Duration
	CommandInactivityTimeout time.Duration
	CommandSlowThreshold     time.Duration
	DemoCaptureExpected      bool
	ProgressWriter           io.Writer
}

func emitProgress(writer io.Writer, format string, args ...any) {
	if writer == nil {
		return
	}
	fmt.Fprintf(writer, format+"\n", args...)
}

func effectiveAzureCommandTimeout(config AzureRunConfig) time.Duration {
	if config.CommandTimeout >= 0 {
		return config.CommandTimeout
	}
	return defaultAzureCommandTimeout
}

func effectiveAzureCommandInactivityTimeout(config AzureRunConfig) time.Duration {
	if config.CommandInactivityTimeout >= 0 {
		return config.CommandInactivityTimeout
	}
	return defaultAzureCommandInactivityTimeout
}

func effectiveAzureSlowCommandThreshold(config AzureRunConfig) time.Duration {
	if config.CommandSlowThreshold >= 0 {
		return config.CommandSlowThreshold
	}
	return defaultAzureSlowCommandThreshold
}

type activityTracker struct {
	mu           sync.Mutex
	lastActivity time.Time
}

func newActivityTracker(start time.Time) *activityTracker {
	return &activityTracker{lastActivity: start}
}

func (t *activityTracker) touch(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at.After(t.lastActivity) {
		t.lastActivity = at
	}
}

func (t *activityTracker) latest() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastActivity
}

type activityWriter struct {
	tracker *activityTracker
	target  io.Writer
}

func (w *activityWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.tracker.touch(time.Now())
	}
	return w.target.Write(p)
}

func latestFilesystemActivity(root string) time.Time {
	latest := time.Time{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		modTime := info.ModTime()
		if modTime.After(latest) {
			latest = modTime
		}
		return nil
	})
	return latest
}

func selectedViewpointsNeedReducedCredentials(viewpoints []string) bool {
	for _, viewpoint := range viewpoints {
		if viewpoint != "admin" {
			return true
		}
	}
	return false
}

func extractValidationViewpoints(entries map[string]tofuOutputEntry) (map[string]map[string]string, error) {
	raw, ok := entries["validation_viewpoints"]
	if !ok {
		return nil, fmt.Errorf("missing tofu output %q", "validation_viewpoints")
	}
	valueMap, ok := raw.Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tofu output %q was not an object", "validation_viewpoints")
	}

	result := map[string]map[string]string{}
	for viewpointName, rawViewpoint := range valueMap {
		viewpointMap, ok := rawViewpoint.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("validation_viewpoints entry %q was not an object", viewpointName)
		}
		normalized := map[string]string{}
		for key, value := range viewpointMap {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("validation_viewpoints entry %q field %q was not a string", viewpointName, key)
			}
			normalized[key] = text
		}
		result[viewpointName] = normalized
	}
	return result, nil
}

func resolveRunContext(config AzureRunConfig, selectedViewpoints []string) (map[string]map[string]string, string, string, error) {
	tenant := config.Tenant
	subscription := config.Subscription

	credentials, err := loadViewpointCredentials(config.ViewpointCredentials)
	if err != nil {
		return nil, "", "", err
	}

	needsReducedCredentials := selectedViewpointsNeedReducedCredentials(selectedViewpoints)
	needsInfraOutputs := (needsReducedCredentials && len(credentials) == 0) || tenant == "" || subscription == ""
	if !needsInfraOutputs {
		return credentials, tenant, subscription, nil
	}

	infraDir := strings.TrimSpace(config.InfraDir)
	if infraDir == "" {
		if needsReducedCredentials && len(credentials) == 0 {
			return nil, "", "", fmt.Errorf("reduced viewpoints need either --viewpoint-credentials or --infra-dir with lab outputs")
		}
		return credentials, tenant, subscription, nil
	}

	tofuBinary := strings.TrimSpace(config.TofuBinary)
	if tofuBinary == "" {
		tofuBinary = "tofu"
	}

	outputs, err := loadTofuOutputs(infraDir, tofuBinary)
	if err != nil {
		return nil, "", "", err
	}

	if needsReducedCredentials && len(credentials) == 0 {
		credentials, err = extractValidationViewpoints(outputs)
		if err != nil {
			return nil, "", "", err
		}
		emitProgress(config.ProgressWriter, "Loaded reduced-viewpoint credentials from lab outputs.")
	}
	if tenant == "" {
		tenant, err = outputString(outputs, "tenant_id")
		if err != nil {
			return nil, "", "", err
		}
	}
	if subscription == "" {
		subscription, err = outputString(outputs, "subscription_id")
		if err != nil {
			return nil, "", "", err
		}
	}

	return credentials, tenant, subscription, nil
}

func executeTask(task SurfaceTask, baseCommand []string, commandCWD, outputDir, tenant, subscription, devopsOrganization string, env []string, timeout, inactivityTimeout time.Duration, progressWriter io.Writer) (CommandLogEntry, string, string) {
	outdir := filepath.Join(outputDir, "artifacts", "payloads", task.SurfaceKind, task.SurfaceName, task.Viewpoint)
	_ = os.MkdirAll(outdir, 0o755)
	payloadPath := filepath.Join(outdir, "stdout.json")
	tablePath := filepath.Join(outdir, "stdout.table.txt")
	csvPath := filepath.Join(outdir, "stdout.csv")
	stderrPath := filepath.Join(outdir, "stderr.txt")
	progressLabel := fmt.Sprintf("%s %s (%s)", task.SurfaceKind, task.SurfaceName, task.Viewpoint)
	startedAt := UTCTimestamp()
	started := time.Now()

	runInvocation := func(invocation []string, artifactPath string) (int, string, error, bool, bool) {
		tracker := newActivityTracker(time.Now())
		var (
			ctx     context.Context
			cancel  context.CancelFunc
			command *exec.Cmd
		)
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(context.Background(), timeout)
			command = exec.CommandContext(ctx, invocation[0], invocation[1:]...)
		} else {
			command = exec.Command(invocation[0], invocation[1:]...)
		}
		if cancel != nil {
			defer cancel()
		}
		command.Dir = commandCWD
		command.Env = env

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		command.Stdout = &activityWriter{tracker: tracker, target: &stdout}
		command.Stderr = &activityWriter{tracker: tracker, target: &stderr}
		if err := command.Start(); err != nil {
			return -1, err.Error(), err, false, false
		}

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- command.Wait()
		}()

		timedOutForInactivity := false
		timeoutReason := ""
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		lastHeartbeat := time.Now()

		var waitErr error
	waitLoop:
		for {
			select {
			case waitErr = <-waitCh:
				break waitLoop
			case <-ticker.C:
				if latest := latestFilesystemActivity(outdir); !latest.IsZero() {
					tracker.touch(latest)
				}
				if time.Since(lastHeartbeat) >= commandProgressHeartbeatInterval {
					emitProgress(progressWriter, "[wait] %s still running (%.0fs elapsed)", progressLabel, time.Since(started).Seconds())
					lastHeartbeat = time.Now()
				}
				if inactivityTimeout > 0 && time.Since(tracker.latest()) > inactivityTimeout {
					timedOutForInactivity = true
					timeoutReason = fmt.Sprintf("command produced no output or artifact updates for %.0f seconds", inactivityTimeout.Seconds())
					_ = command.Process.Kill()
					waitErr = <-waitCh
					break waitLoop
				}
			}
		}

		stderrText := ""
		exitCode := 0
		timedOutForDeadline := false
		if timedOutForInactivity {
			exitCode = -1
			stderrText = timeoutReason
		} else if waitErr != nil {
			if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				exitCode = -1
				timedOutForDeadline = true
				stderrText = fmt.Sprintf("command timed out after %.0f seconds", timeout.Seconds())
			} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
				stderrText = stderr.String()
				exitCode = exitErr.ExitCode()
			} else {
				stderrText = waitErr.Error()
				exitCode = -1
			}
		}

		if stdout.Len() > 0 {
			_ = os.WriteFile(artifactPath, stdout.Bytes(), 0o644)
		}
		if exitCode != 0 || stderrText != "" {
			_ = os.WriteFile(stderrPath, []byte(stderrText), 0o644)
		}
		return exitCode, stderrText, waitErr, timedOutForInactivity, timedOutForDeadline
	}

	jsonInvocation := BuildInvocation(baseCommand, task, outdir, tenant, subscription, devopsOrganization, "json", true)
	emitProgress(progressWriter, "[start] %s -> %s", progressLabel, outdir)
	jsonExitCode, _, jsonErr, jsonInactivityTimeout, jsonDeadlineTimeout := runInvocation(jsonInvocation, payloadPath)

	status := "pass"
	notes := "Live run succeeded."
	if jsonInactivityTimeout {
		status = "fail"
		notes = fmt.Sprintf("Live run went quiet for %.0f seconds with no output or artifact updates. Treat this as a possible hang or performance issue, not a confirmed root cause. Rerun with a longer inactivity timeout or disable it before upstream handoff if no likely fix is obvious.", inactivityTimeout.Seconds())
	} else if jsonDeadlineTimeout {
		status = "fail"
		notes = fmt.Sprintf("Live run timed out after %.0f seconds. Treat this as a possible hang or performance issue, not a confirmed root cause. Rerun with a longer timeout or no timeout before upstream handoff if no likely fix is obvious.", timeout.Seconds())
	} else if jsonExitCode != 0 {
		status = "fail"
		if jsonErr != nil && jsonExitCode == -1 {
			notes = "Live run failed to start. See error details."
		} else {
			notes = fmt.Sprintf("Live run failed with exit code %d. See stderr artifact.", jsonExitCode)
		}
	}

	tableInvocation := BuildInvocation(baseCommand, task, outdir, tenant, subscription, devopsOrganization, "table", true)
	tableExitCode := 0
	if status == "pass" {
		var tableInactivityTimeout bool
		var tableDeadlineTimeout bool
		tableExitCode, _, _, tableInactivityTimeout, tableDeadlineTimeout = runInvocation(tableInvocation, tablePath)
		if tableInactivityTimeout {
			status = "fail"
			notes = fmt.Sprintf("JSON run succeeded, but the table rerun went quiet for %.0f seconds with no output or artifact updates. Treat table-versus-payload review as blocked until the table artifact is usable.", inactivityTimeout.Seconds())
		} else if tableDeadlineTimeout {
			status = "fail"
			notes = fmt.Sprintf("JSON run succeeded, but the table rerun timed out after %.0f seconds. Treat table-versus-payload review as blocked until the table artifact is usable.", timeout.Seconds())
		} else if tableExitCode != 0 {
			status = "fail"
			notes = fmt.Sprintf("JSON run succeeded, but the table rerun failed with exit code %d. Treat table-versus-payload review as blocked until the table artifact is usable.", tableExitCode)
		}
	}

	csvInvocation := BuildInvocation(baseCommand, task, outdir, tenant, subscription, devopsOrganization, "csv", true)
	csvExitCode := 0
	if status == "pass" {
		var csvInactivityTimeout bool
		var csvDeadlineTimeout bool
		csvExitCode, _, _, csvInactivityTimeout, csvDeadlineTimeout = runInvocation(csvInvocation, csvPath)
		if csvInactivityTimeout {
			status = "fail"
			notes = fmt.Sprintf("JSON and table runs succeeded, but the CSV rerun went quiet for %.0f seconds with no output or artifact updates. Treat CSV-versus-payload review as blocked until the CSV artifact is usable.", inactivityTimeout.Seconds())
		} else if csvDeadlineTimeout {
			status = "fail"
			notes = fmt.Sprintf("JSON and table runs succeeded, but the CSV rerun timed out after %.0f seconds. Treat CSV-versus-payload review as blocked until the CSV artifact is usable.", timeout.Seconds())
		} else if csvExitCode != 0 {
			status = "fail"
			notes = fmt.Sprintf("JSON and table runs succeeded, but the CSV rerun failed with exit code %d. Treat CSV-versus-payload review as blocked until the CSV artifact is usable.", csvExitCode)
		}
	}

	finishedAt := UTCTimestamp()
	durationSeconds := time.Since(started).Seconds()
	reportedExitCode := jsonExitCode
	if status == "fail" && tableExitCode != 0 {
		reportedExitCode = tableExitCode
	}
	if status == "fail" && csvExitCode != 0 {
		reportedExitCode = csvExitCode
	}
	entryError := ""
	if jsonErr != nil && reportedExitCode == jsonExitCode {
		entryError = jsonErr.Error()
	}
	entry := CommandLogEntry{
		SurfaceKind:     task.SurfaceKind,
		SurfaceName:     task.SurfaceName,
		Viewpoint:       task.Viewpoint,
		Command:         strings.Join(jsonInvocation, " "),
		Status:          status,
		ExitCode:        reportedExitCode,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
		DurationSeconds: durationSeconds,
		PayloadPath:     "",
		TablePath:       "",
		CSVPath:         "",
		StderrPath:      "",
		Error:           entryError,
	}
	if _, err := os.Stat(payloadPath); err == nil {
		entry.PayloadPath = artifactRelpath(outputDir, payloadPath)
	}
	if _, err := os.Stat(tablePath); err == nil {
		entry.TablePath = artifactRelpath(outputDir, tablePath)
	}
	if _, err := os.Stat(csvPath); err == nil {
		entry.CSVPath = artifactRelpath(outputDir, csvPath)
	}
	if _, err := os.Stat(stderrPath); err == nil {
		entry.StderrPath = artifactRelpath(outputDir, stderrPath)
	}
	emitProgress(progressWriter, "[done] %s -> status=%s duration=%.0fs", progressLabel, status, durationSeconds)
	return entry, status, notes
}

func RunAzureValidation(config AzureRunConfig) (int, error) {
	emitProgress(config.ProgressWriter, "Starting Azure execution...")
	var manifest Manifest
	if err := LoadJSON(config.ManifestPath, &manifest); err != nil {
		return 1, err
	}
	derivedSurface, err := DeriveSurface(config.HOAzureDir)
	if err != nil {
		return 1, err
	}
	emitProgress(config.ProgressWriter, "Loaded manifest and current HO-Azure surface.")

	outputDir := config.OutputDir
	baseCommand, commandCWD, cleanupToolBinary, err := ResolveBaseCommand(config.HOAzureDir, config.ToolBin, config.ProgressWriter)
	if err != nil {
		return 1, err
	}
	if cleanupToolBinary != nil {
		defer cleanupToolBinary()
	}
	if strings.TrimSpace(config.ToolBin) != "" {
		emitProgress(config.ProgressWriter, "Using HO-Azure binary: %s", config.ToolBin)
	} else {
		emitProgress(config.ProgressWriter, "Built a fresh HO-Azure binary from source for this validation run.")
	}
	runResult, err := ScaffoldRun(manifest, outputDir, config.RunID, config.DemoCaptureExpected)
	if err != nil {
		return 1, err
	}
	runResult.StartedAt = UTCTimestamp()
	runResult.FinishedAt = runResult.StartedAt

	selectedViewpoints := SelectedViewpoints(manifest, config.Viewpoint)
	runProfile, tasks, err := BuildRunProfile(manifest, derivedSurface, config.RunID, config.RunProfile, selectedViewpoints, config.CommandSelectors, config.FamilySelectors)
	if err != nil {
		return 1, err
	}
	credentials, tenant, subscription, err := resolveRunContext(config, selectedViewpoints)
	if err != nil {
		return 1, err
	}
	emitProgress(config.ProgressWriter, "Running %d covered checks for profile %s and viewpoints: %s", len(tasks), runProfile.Profile, strings.Join(selectedViewpoints, ", "))
	commandTimeout := effectiveAzureCommandTimeout(config)
	commandInactivityTimeout := effectiveAzureCommandInactivityTimeout(config)
	commandSlowThreshold := effectiveAzureSlowCommandThreshold(config)

	entries := []CommandLogEntry{}
	if err := WriteRunProfile(outputDir, runProfile); err != nil {
		return 1, err
	}
	runResult.Artifacts["run_profile"] = ArtifactRecord{Path: "artifacts/run-profile.json"}
	if err := WriteCommandLog(outputDir, config.RunID, entries); err != nil {
		return 1, err
	}
	if err := WriteCommandTimeline(outputDir, runResult, entries); err != nil {
		return 1, err
	}
	if err := UpdateRunResultPath(outputDir, runResult); err != nil {
		return 1, err
	}

	for taskIndex, task := range tasks {
		emitProgress(config.ProgressWriter, "check %d/%d: %s %s %s", taskIndex+1, len(tasks), task.SurfaceKind, task.SurfaceName, task.Viewpoint)
		env := envWithOverrides("AZUREFOX_PROVIDER=azure")
		taskTenant := tenant
		taskSubscription := subscription
		tempConfigDir := ""

		func() {
			defer func() {
				if tempConfigDir != "" {
					_ = os.RemoveAll(tempConfigDir)
				}
			}()

			viewpoint := task.Viewpoint
			if viewpoint == "admin" {
				var err error
				tempConfigDir, env, taskTenant, taskSubscription, err = setupAdminAmbientSession(tenant, subscription, commandCWD, config.ProgressWriter)
				if err != nil {
					entry := CommandLogEntry{
						SurfaceKind:     task.SurfaceKind,
						SurfaceName:     task.SurfaceName,
						Viewpoint:       viewpoint,
						Command:         task.GroupCommand,
						Status:          "fail",
						ExitCode:        -1,
						StartedAt:       UTCTimestamp(),
						FinishedAt:      UTCTimestamp(),
						DurationSeconds: 0,
						Error:           err.Error(),
					}
					entries = append(entries, entry)
					runResult.SurfaceResultsSection(task.SurfaceKind)[task.SurfaceName][viewpoint] = ViewpointResult{Status: "fail", Notes: err.Error()}
					return
				}
			} else {
				credentialKey := viewpointCredentialKeys[viewpoint]
				viewpointCredentials, ok := credentials[credentialKey]
				if !ok {
					entry := CommandLogEntry{
						SurfaceKind:     task.SurfaceKind,
						SurfaceName:     task.SurfaceName,
						Viewpoint:       viewpoint,
						Command:         task.GroupCommand,
						Status:          "fail",
						ExitCode:        -1,
						StartedAt:       UTCTimestamp(),
						FinishedAt:      UTCTimestamp(),
						DurationSeconds: 0,
						Error:           fmt.Sprintf("%s viewpoint needs --viewpoint-credentials with a %s entry", viewpoint, credentialKey),
					}
					entries = append(entries, entry)
					runResult.SurfaceResultsSection(task.SurfaceKind)[task.SurfaceName][viewpoint] = ViewpointResult{Status: "fail", Notes: entry.Error}
					return
				}
				var err error
				tempConfigDir, env, taskTenant, taskSubscription, err = setupViewpointSession(viewpoint, viewpointCredentials, tenant, subscription, commandCWD, config.ProgressWriter)
				if err != nil {
					entry := CommandLogEntry{
						SurfaceKind:     task.SurfaceKind,
						SurfaceName:     task.SurfaceName,
						Viewpoint:       viewpoint,
						Command:         task.GroupCommand,
						Status:          "fail",
						ExitCode:        -1,
						StartedAt:       UTCTimestamp(),
						FinishedAt:      UTCTimestamp(),
						DurationSeconds: 0,
						Error:           err.Error(),
					}
					entries = append(entries, entry)
					runResult.SurfaceResultsSection(task.SurfaceKind)[task.SurfaceName][viewpoint] = ViewpointResult{Status: "fail", Notes: err.Error()}
					return
				}
			}

			entry, status, notes := executeTask(task, baseCommand, commandCWD, outputDir, taskTenant, taskSubscription, config.DevOpsOrganization, env, commandTimeout, commandInactivityTimeout, config.ProgressWriter)
			if status == "pass" {
				taskOutdir := filepath.Join(outputDir, "artifacts", "payloads", task.SurfaceKind, task.SurfaceName, task.Viewpoint)
				if err := captureLiveAzureContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
					status = "fail"
					notes = fmt.Sprintf("Live run captured a payload, but the Azure-backed validation context could not be recorded: %s", err)
					entry.Status = "fail"
					entry.ExitCode = -1
					entry.Error = err.Error()
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "managed-identities" {
					if err := captureLiveManagedIdentitiesContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the managed-identities validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "workloads" {
					if err := captureLiveWorkloadsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the workloads validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "app-services" {
					if err := captureLiveAppServicesContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the app-services validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "functions" {
					if err := captureLiveFunctionsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the functions validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "env-vars" {
					if err := captureLiveEnvVarsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the env-vars validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "auth-policies" {
					if err := captureLiveAuthPoliciesContext(taskOutdir, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the auth-policies validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "cross-tenant" {
					if err := captureLiveCrossTenantContext(taskOutdir, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the cross-tenant validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "role-trusts" {
					if err := captureLiveRoleTrustsContext(taskOutdir, config.InfraDir, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the role-trusts validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "tokens-credentials" {
					if err := captureLiveTokensCredentialsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the tokens-credentials validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "app-credentials" {
					if err := captureLiveAppCredentialsContext(taskOutdir, config.InfraDir, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the app-credentials validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "arm-deployments" {
					if err := captureLiveArmDeploymentsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the arm-deployments validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "dns" {
					if err := captureLiveDNSContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the dns validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "endpoints" {
					if err := captureLiveEndpointsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the endpoints validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "network-effective" {
					if err := captureLiveNetworkEffectiveContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the network-effective validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "network-ports" {
					if err := captureLiveNetworkPortsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the network-ports validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "container-apps" {
					if err := captureLiveContainerAppsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the container-apps validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "container-instances" {
					if err := captureLiveContainerInstancesContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the container-instances validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "inventory" {
					if err := captureLiveInventoryContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the inventory validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "logic-apps" {
					if err := captureLiveLogicAppsContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the logic-apps validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "automation" {
					if err := captureLiveAutomationContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the automation validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "azure-ml" {
					if err := captureLiveAzureMLContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the azure-ml validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "event-grid" {
					if err := captureLiveEventGridContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the event-grid validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "api-mgmt" {
					if err := captureLiveAPIMgmtContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the api-mgmt validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "application-gateway" {
					if err := captureLiveApplicationGatewayContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the application-gateway validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "databases" {
					if err := captureLiveDatabasesContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the databases validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "keyvault" {
					if err := captureLiveKeyVaultContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the keyvault validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "resource-trusts" {
					if err := captureLiveKeyVaultContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the resource-trusts keyvault validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
					if status == "pass" {
						if err := captureLiveStorageContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
							status = "fail"
							notes = fmt.Sprintf("Live run captured a payload, but the resource-trusts storage validation context could not be recorded: %s", err)
							entry.Status = "fail"
							entry.ExitCode = -1
							entry.Error = err.Error()
						}
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "storage" {
					if err := captureLiveStorageContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the storage validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "snapshots-disks" {
					if err := captureLiveSnapshotsDisksContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the snapshots-disks validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "nics" {
					if err := captureLiveNICContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the nics validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "vms" {
					if err := captureLiveVMSContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the vms validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "vmss" {
					if err := captureLiveVMSSContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the vmss validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "acr" {
					if err := captureLiveACRContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the acr validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "commands" && task.SurfaceName == "aks" {
					if err := captureLiveAKSContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the aks validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "families" && task.SurfaceName == "credential-path" {
					if err := captureLiveCredentialPathContext(taskOutdir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the credential-path validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
				if status == "pass" && task.SurfaceKind == "families" && task.SurfaceName == "compute-control" {
					if err := captureLiveComputeControlContext(taskOutdir, config.InfraDir, commandCWD, env, config.ProgressWriter); err != nil {
						status = "fail"
						notes = fmt.Sprintf("Live run captured a payload, but the compute-control validation context could not be recorded: %s", err)
						entry.Status = "fail"
						entry.ExitCode = -1
						entry.Error = err.Error()
					}
				}
			}
			if status == "pass" && commandSlowThreshold > 0 && entry.DurationSeconds > commandSlowThreshold.Seconds() {
				notes = fmt.Sprintf("Live run succeeded, but it took %.0f seconds and exceeded the slow-command threshold of %.0f seconds. Treat this as a performance issue to review even though the command kept making progress.", entry.DurationSeconds, commandSlowThreshold.Seconds())
				runResult.Findings = append(runResult.Findings, Finding{
					ID:              fmt.Sprintf("slow-%s-%s-%s", task.SurfaceKind, task.SurfaceName, task.Viewpoint),
					Owner:           "tool",
					Severity:        "medium",
					Summary:         fmt.Sprintf("%s %s for viewpoint %s completed after %.0f seconds, exceeding the slow-command threshold of %.0f seconds", task.SurfaceKind, task.SurfaceName, task.Viewpoint, entry.DurationSeconds, commandSlowThreshold.Seconds()),
					LikelySeam:      "command performance or repeated API walking",
					ExpectedOutcome: "Either keep the runtime under the maintained threshold or document and bound why the slower path is acceptable.",
				})
			}
			entries = append(entries, entry)
			runResult.SurfaceResultsSection(task.SurfaceKind)[task.SurfaceName][viewpoint] = ViewpointResult{Status: status, Notes: notes}
		}()

		runResult.FinishedAt = UTCTimestamp()
		if err := WriteCommandLog(outputDir, config.RunID, entries); err != nil {
			return 1, err
		}
		if err := WriteCommandTimeline(outputDir, runResult, entries); err != nil {
			return 1, err
		}
		if err := UpdateRunResultPath(outputDir, runResult); err != nil {
			return 1, err
		}
	}

	anyFailures := false
	for _, entry := range entries {
		if entry.Status != "pass" {
			anyFailures = true
			break
		}
	}
	if anyFailures {
		runResult.FinalOutcome = "blocked"
	} else if len(runResult.Findings) > 0 {
		runResult.FinalOutcome = "fix-now"
	} else {
		runResult.FinalOutcome = "pass"
	}
	runResult.FinishedAt = UTCTimestamp()
	if err := WriteCommandLog(outputDir, config.RunID, entries); err != nil {
		return 1, err
	}
	if err := WriteCommandTimeline(outputDir, runResult, entries); err != nil {
		return 1, err
	}
	if err := UpdateRunResultPath(outputDir, runResult); err != nil {
		return 1, err
	}
	if anyFailures {
		emitProgress(config.ProgressWriter, "Azure execution finished with blocking issues. Review the run artifacts before continuing.")
		return 1, nil
	}
	if len(runResult.Findings) > 0 {
		emitProgress(config.ProgressWriter, "Azure execution finished with performance or review findings. Review the run artifacts before continuing.")
		return 1, nil
	}
	emitProgress(config.ProgressWriter, "Azure execution finished successfully.")
	return 0, nil
}

func (r *RunResult) SurfaceResultsSection(kind string) map[string]map[string]ViewpointResult {
	if kind == "families" {
		return r.SurfaceResults.Families
	}
	return r.SurfaceResults.Commands
}

func SaveLiveValidationSummary(runResultsPath, outputPath string, summary LiveValidationSummary, writeRunResults bool) (int, error) {
	if outputPath == "" {
		outputPath = filepath.Join(filepath.Dir(runResultsPath), "artifacts", "live-validation-summary.json")
	}
	if err := WriteJSON(outputPath, summary); err != nil {
		return 1, err
	}
	if writeRunResults {
		var runResults RunResult
		if err := LoadJSON(runResultsPath, &runResults); err != nil {
			return 1, err
		}
		runResults.Findings = MergeFindings(runResults.Findings, summary.Findings)
		if summary.FindingCount > 0 && (runResults.FinalOutcome == "pass" || runResults.FinalOutcome == "pass_with_explicit_exceptions") {
			runResults.FinalOutcome = "fix-now"
		}
		if err := WriteJSON(runResultsPath, runResults); err != nil {
			return 1, err
		}
	}
	if summary.FindingCount > 0 {
		return 1, nil
	}
	return 0, nil
}

func MergeFindings(existing, incoming []Finding) []Finding {
	merged := map[string]Finding{}
	for _, finding := range existing {
		merged[finding.ID] = finding
	}
	for _, finding := range incoming {
		merged[finding.ID] = finding
	}
	ids := make([]string, 0, len(merged))
	for id := range merged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]Finding, 0, len(ids))
	for _, id := range ids {
		result = append(result, merged[id])
	}
	return result
}

func writeText(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func RunValidation(config AzureRunConfig) (int, error) {
	emitProgress(config.ProgressWriter, "Starting Azure validation flow...")
	runExitCode, err := RunAzureValidation(config)
	if err != nil {
		return 1, err
	}

	runResultsPath := filepath.Join(config.OutputDir, "run-result.json")
	emitProgress(config.ProgressWriter, "Running live payload checks...")
	liveSummary, err := ValidateLiveRun(runResultsPath, config.HOAzureDir)
	if err != nil {
		return 1, err
	}
	liveSummaryPath := filepath.Join(config.OutputDir, "artifacts", "live-validation-summary.json")
	liveExitCode, err := SaveLiveValidationSummary(runResultsPath, liveSummaryPath, liveSummary, true)
	if err != nil {
		return 1, err
	}

	emitProgress(config.ProgressWriter, "Running completion verification...")
	validationSummary, err := ValidateLab(config.ManifestPath, config.HOAzureDir, runResultsPath)
	if err != nil {
		return 1, err
	}
	validationSummaryPath := filepath.Join(config.OutputDir, "artifacts", "completion-summary.json")
	if err := WriteJSON(validationSummaryPath, validationSummary); err != nil {
		return 1, err
	}
	validationTextPath := filepath.Join(config.OutputDir, "artifacts", "completion-summary.txt")
	if err := writeText(validationTextPath, RenderText(validationSummary)); err != nil {
		return 1, err
	}

	if runExitCode != 0 || liveExitCode != 0 || validationSummary.CompletionStatus != "complete" {
		emitProgress(config.ProgressWriter, "Azure validation found issues. Review the completion summary and findings before release.")
		return 1, nil
	}
	if validationSummary.ReleaseReady {
		emitProgress(config.ProgressWriter, "Azure validation succeeded. The run artifacts and summaries are ready to review.")
	} else {
		emitProgress(config.ProgressWriter, "Azure validation completed for the selected run profile. Review the completion summary before treating it as release proof.")
	}
	return 0, nil
}
