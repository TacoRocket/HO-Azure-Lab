package lab

type SurfaceSnapshot struct {
	GeneratedAt           string              `json:"generated_at"`
	ToolRepoPath          string              `json:"tool_repo_path"`
	Commands              []string            `json:"commands"`
	Families              []string            `json:"families"`
	FamilyGroupCommands   map[string]string   `json:"family_group_commands"`
	CommandTopLevelFields map[string][]string `json:"command_top_level_fields"`
}

type ToolInfo struct {
	Name          string `json:"name"`
	RepoPath      string `json:"repo_path"`
	SurfaceSource string `json:"surface_source"`
}

type ViewpointDefinition struct {
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type ViewpointStatus struct {
	Status       string `json:"status"`
	ReasonCode   string `json:"reason_code,omitempty"`
	ReasonDetail string `json:"reason_detail,omitempty"`
}

type SurfaceEntry struct {
	Status           string                     `json:"status"`
	ReasonCode       string                     `json:"reason_code,omitempty"`
	ReasonDetail     string                     `json:"reason_detail,omitempty"`
	ManualSetupSteps []string                   `json:"manual_setup_steps,omitempty"`
	Viewpoints       map[string]ViewpointStatus `json:"viewpoints"`
}

type ArtifactRequirement struct {
	ID           string `json:"id"`
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	RequiredWhen string `json:"required_when"`
}

type ReviewTopic struct {
	ID     string `json:"id"`
	Prompt string `json:"prompt"`
}

type CompletionContract struct {
	RequireFinalOutcome  bool                  `json:"require_final_outcome"`
	RequireFindings      bool                  `json:"require_findings"`
	RequireTeardown      bool                  `json:"require_teardown_record"`
	RequiredArtifacts    []ArtifactRequirement `json:"required_artifacts"`
	RequiredReviewTopics []ReviewTopic         `json:"required_review_topics"`
}

type SurfaceCatalog struct {
	Commands map[string]SurfaceEntry `json:"commands"`
	Families map[string]SurfaceEntry `json:"families"`
}

type Manifest struct {
	ManifestVersion int                            `json:"manifest_version"`
	Tool            ToolInfo                       `json:"tool"`
	Viewpoints      map[string]ViewpointDefinition `json:"viewpoints"`
	Surfaces        SurfaceCatalog                 `json:"surfaces"`
	Completion      CompletionContract             `json:"completion"`
}

type ScopeSummary struct {
	Covered             []string            `json:"covered"`
	ExceptedByReason    map[string][]string `json:"excepted_by_reason"`
	UnsupportedByReason map[string][]string `json:"unsupported_by_reason"`
}

type RunScope struct {
	RequiredViewpoints []string     `json:"required_viewpoints"`
	Commands           ScopeSummary `json:"commands"`
	Families           ScopeSummary `json:"families"`
}

type ViewpointResult struct {
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

type RunSurfaceResults struct {
	Commands map[string]map[string]ViewpointResult `json:"commands"`
	Families map[string]map[string]ViewpointResult `json:"families"`
}

type ArtifactRecord struct {
	Path string `json:"path"`
}

type Finding struct {
	ID              string `json:"id"`
	Owner           string `json:"owner,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Summary         string `json:"summary"`
	WhyBlocking     string `json:"why_blocking,omitempty"`
	LikelySeam      string `json:"likely_seam,omitempty"`
	ExpectedOutcome string `json:"expected_outcome,omitempty"`
}

type TeardownRecord struct {
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

type RunResult struct {
	RunID               string                    `json:"run_id"`
	StartedAt           string                    `json:"started_at"`
	FinishedAt          string                    `json:"finished_at"`
	DemoCaptureExpected bool                      `json:"demo_capture_expected"`
	Scope               RunScope                  `json:"scope"`
	SurfaceResults      RunSurfaceResults         `json:"surface_results"`
	Artifacts           map[string]ArtifactRecord `json:"artifacts"`
	FinalOutcome        string                    `json:"final_outcome"`
	Findings            []Finding                 `json:"findings"`
	Teardown            TeardownRecord            `json:"teardown"`
}

type CommandLogEntry struct {
	SurfaceKind     string  `json:"surface_kind"`
	SurfaceName     string  `json:"surface_name"`
	Viewpoint       string  `json:"viewpoint"`
	Command         string  `json:"command"`
	Status          string  `json:"status"`
	ExitCode        int     `json:"exit_code"`
	StartedAt       string  `json:"started_at"`
	FinishedAt      string  `json:"finished_at"`
	DurationSeconds float64 `json:"duration_seconds"`
	PayloadPath     string  `json:"payload_path"`
	TablePath       string  `json:"table_path,omitempty"`
	StderrPath      string  `json:"stderr_path"`
	Error           string  `json:"error,omitempty"`
}

type CommandLog struct {
	RunID      string            `json:"run_id"`
	EntryCount int               `json:"entry_count"`
	Entries    []CommandLogEntry `json:"entries"`
}

type CommandTimeline struct {
	RunID      string            `json:"run_id"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
	Scope      RunScope          `json:"scope"`
	EntryCount int               `json:"entry_count"`
	Entries    []CommandLogEntry `json:"entries"`
}

type SurfaceTask struct {
	SurfaceKind  string
	SurfaceName  string
	Viewpoint    string
	GroupCommand string
	Subcommand   string
}

type ValidationSummary struct {
	CompletionStatus       string                    `json:"completion_status"`
	ReleaseReady           bool                      `json:"release_ready"`
	AutomaticPasses        []string                  `json:"automatic_passes"`
	AutomaticFailures      []string                  `json:"automatic_failures"`
	RequiredReviewTopics   []ReviewTopic             `json:"required_review_topics"`
	ToolRepoHandoffPrompts []ToolRepoHandoffPrompt   `json:"tool_repo_handoff_prompts"`
	Summary                ValidationSummaryEnvelope `json:"summary"`
	Warnings               []string                  `json:"warnings"`
}

type ToolRepoHandoffPrompt struct {
	FindingID string `json:"finding_id"`
	Prompt    string `json:"prompt"`
}

type StatusBreakdown struct {
	Counts   map[string]int      `json:"counts"`
	ByReason map[string][]string `json:"by_reason"`
}

type ValidationSummaryEnvelope struct {
	RequiredViewpoints  []string        `json:"required_viewpoints"`
	ShippedCommandCount int             `json:"shipped_command_count"`
	ShippedFamilyCount  int             `json:"shipped_family_count"`
	Commands            StatusBreakdown `json:"commands"`
	Families            StatusBreakdown `json:"families"`
}

type LiveValidationSummary struct {
	CheckedPayloadCount int       `json:"checked_payload_count"`
	CheckedPayloads     []string  `json:"checked_payloads"`
	FindingCount        int       `json:"finding_count"`
	Findings            []Finding `json:"findings"`
}
