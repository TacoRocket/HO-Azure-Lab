package contracts

import "sort"

type FamilySourceContract struct {
	Command       string
	MinimumFields []string
	Rationale     string
}

type FamilyContract struct {
	GroupedCommand       string
	Name                 string
	Status               string
	Meaning              string
	Summary              string
	AllowedClaim         string
	CurrentGap           string
	BestCurrentExamples  []string
	BackingCommands      []string
	PreferredArtifacts   []string
	StructuredRowFields  []string
	OperatorQuestion     string
	SourceCommandMinimum []FamilySourceContract
}

var familyContracts = map[string]FamilyContract{
	"credential-path": {
		GroupedCommand: "chains",
		Name:           "credential-path",
		Status:         StatusImplemented,
		Meaning:        "A workload, configuration surface, artifact, or nearby service exposes a usable or near-usable credential path toward a downstream target.",
		Summary:        "Follow credential clues from surfaced secret-bearing or token-bearing evidence toward the likely downstream service.",
		AllowedClaim:   "Can claim that the visible evidence suggests a likely credential path and name the most plausible downstream service. Cannot claim the exact downstream target or that the setting is confirmed to reach it.",
		CurrentGap:     "The live family now joins backing evidence in one run, but it still needs periodic review so rows that only restate a source clue do not survive as fake grouped value.",
		BestCurrentExamples: []string{
			"env-vars -> tokens-credentials -> databases",
			"env-vars -> tokens-credentials -> storage",
		},
		BackingCommands:    []string{"env-vars", "tokens-credentials", "databases", "storage", "keyvault"},
		PreferredArtifacts: []string{"loot", "json"},
		StructuredRowFields: []string{
			"start_state",
			"source_command",
			"target_service",
			"confidence_boundary",
			"missing_proof",
			"next_review",
			"summary",
		},
		OperatorQuestion: "Which visible workload or config clue most plausibly leads to a downstream credential-bearing target?",
		SourceCommandMinimum: []FamilySourceContract{
			{Command: "env-vars", MinimumFields: []string{"asset_id", "asset_name", "setting_name", "value_type", "reference_target", "workload_identity_ids"}, Rationale: "Provides the first credential-shaped or secret-dependency clue on the workload."},
			{Command: "tokens-credentials", MinimumFields: []string{"asset_id", "asset_name", "surface_type", "access_path", "priority", "operator_signal"}, Rationale: "Confirms whether the same workload already looks like a direct credential or token path."},
			{Command: "databases", MinimumFields: []string{"id", "name", "engine", "fully_qualified_domain_name", "user_database_names"}, Rationale: "Provides likely relational target services when the credential clue points toward a data path."},
			{Command: "storage", MinimumFields: []string{"id", "name", "public_access", "allow_shared_key_access", "container_count", "file_share_count"}, Rationale: "Provides likely storage targets when the surfaced credential story points to blob, file, or account access."},
			{Command: "keyvault", MinimumFields: []string{"id", "name", "vault_uri", "public_network_access", "enable_rbac_authorization", "access_policy_count"}, Rationale: "Provides the upstream secret-store boundary when the workload depends on Key Vault rather than exposing the secret directly."},
		},
	},
	"deployment-path": {
		GroupedCommand: "chains",
		Name:           "deployment-path",
		Status:         StatusImplemented,
		Meaning:        "A supply-chain or automation source already looks capable of changing Azure state, redeploying workloads, or reintroducing access.",
		Summary:        "Follow controllable deployment and automation paths toward the Azure footprint they are most likely to change next.",
		AllowedClaim:   "Can claim that the visible evidence suggests a controllable or nearly controllable Azure change path and can name or narrow the likely downstream footprint when the join is honest. Cannot claim successful execution or the exact downstream Azure change from current visible evidence alone.",
		CurrentGap:     "The live family still needs stronger source-side actionability proof and tighter downstream target joins before every row reads like a defended change path instead of review-heavy deployment context.",
		BestCurrentExamples: []string{
			"devops -> permissions -> arm-deployments",
			"devops -> aks",
			"automation -> permissions",
		},
		BackingCommands:    []string{"devops", "automation", "permissions", "rbac", "role-trusts", "keyvault", "arm-deployments", "aks", "functions", "app-services"},
		PreferredArtifacts: []string{"loot", "json"},
		StructuredRowFields: []string{
			"source",
			"actionability",
			"insertion_point_display",
			"likely_azure_impact",
			"whats_missing",
			"next_review",
			"confidence_boundary",
			"note",
		},
		OperatorQuestion: "Which visible automation or supply-chain path can most honestly be described as a controllable Azure change path?",
		SourceCommandMinimum: []FamilySourceContract{
			{Command: "devops", MinimumFields: []string{"id", "name", "project_name", "azure_service_connection_names", "target_clues", "risk_cues"}, Rationale: "Provides the strongest current named Azure change-path clues from build definitions and service connections."},
			{Command: "automation", MinimumFields: []string{"id", "name", "identity_type", "published_runbook_count", "schedule_count", "webhook_count"}, Rationale: "Provides Azure-native automation hubs that may already be able to execute or reintroduce change."},
			{Command: "permissions", MinimumFields: []string{"principal_id", "principal_type", "high_impact_roles", "scope_count", "privileged"}, Rationale: "Provides direct RBAC proof for automation identities and service-connection-backed principals."},
			{Command: "rbac", MinimumFields: []string{"scope_id", "principal_id", "role_name"}, Rationale: "Provides exact role-to-scope evidence for the current identity when the family needs to prove start or edit control on an automation path."},
			{Command: "role-trusts", MinimumFields: []string{"source_object_id", "target_object_id", "trust_type", "confidence", "summary"}, Rationale: "Provides trust-expansion context when the deployment identity can also control other app or service-principal boundaries."},
			{Command: "keyvault", MinimumFields: []string{"name", "vault_uri", "public_network_access", "enable_rbac_authorization", "access_policy_count"}, Rationale: "Provides the visible secret-store boundary when the deployment path relies on Key Vault-backed variable or input support."},
			{Command: "arm-deployments", MinimumFields: []string{"id", "name", "scope", "outputs_count", "providers", "summary"}, Rationale: "Provides deployment history and target clues that help explain what Azure state a pipeline or automation path may affect."},
			{Command: "aks", MinimumFields: []string{"id", "name", "cluster_identity_ids", "private_cluster_enabled", "workload_identity_enabled", "summary"}, Rationale: "Provides high-value cluster targets when the deployment path looks Kubernetes or workload-platform oriented."},
			{Command: "functions", MinimumFields: []string{"id", "name", "default_hostname", "workload_identity_ids", "azure_webjobs_storage_value_type", "summary"}, Rationale: "Provides deployable workload targets with identity and runtime clues when the path points toward serverless workloads."},
			{Command: "app-services", MinimumFields: []string{"id", "name", "default_hostname", "workload_identity_ids", "public_network_access", "summary"}, Rationale: "Provides App Service targets when the deployment path points toward web application change rather than infrastructure-only change."},
		},
	},
	"escalation-path": {
		GroupedCommand: "chains",
		Name:           "escalation-path",
		Status:         StatusImplemented,
		Meaning:        "A current foothold, trust edge, or bounded support clue already suggests a stronger identity or control path in Azure.",
		Summary:        "Follow the strongest current-foothold escalation stories toward the next defended identity or control step.",
		AllowedClaim:   "Can claim that visible evidence suggests a current-foothold escalation story and can name what stronger control or trust consequence is in view. Cannot claim exploit success or multi-hop control without deeper evidence.",
		CurrentGap:     "The live family now joins current-foothold control, trust takeover, federated trust, and app-permission reach when the transform and stronger Azure control are explicit. Broader secret-bearing or support-only starts still sit outside this family, and ranking is still heuristic within the admitted current-foothold paths.",
		BestCurrentExamples: []string{
			"permissions",
			"permissions -> role-trusts",
		},
		BackingCommands:    []string{"permissions", "role-trusts"},
		PreferredArtifacts: []string{"loot", "json"},
		StructuredRowFields: []string{
			"starting_foothold",
			"stronger_outcome",
			"path_type",
			"confidence_boundary",
			"missing_confirmation",
			"next_review",
			"summary",
		},
		OperatorQuestion: "What is the best defended escalation lead available from the current foothold?",
		SourceCommandMinimum: []FamilySourceContract{
			{Command: "permissions", MinimumFields: []string{"principal_id", "display_name", "priority", "high_impact_roles", "scope_count", "scope_ids", "privileged", "is_current_identity"}, Rationale: "Provides the direct current-identity and visible Azure-control evidence that anchors the chain family's starting foothold."},
			{Command: "role-trusts", MinimumFields: []string{"trust_type", "source_object_id", "target_object_id", "confidence", "summary"}, Rationale: "Provides trust edges that can widen a current-foothold path into stronger identity control when that edge is actually connected."},
		},
	},
	"compute-control": {
		GroupedCommand: "chains",
		Name:           "compute-control",
		Status:         StatusImplemented,
		Meaning:        "A token-capable compute foothold can already act as an attached identity and that identity already maps to stronger Azure control.",
		Summary:        "Follow token-capable compute footholds toward the identity-backed Azure control they can reach next.",
		AllowedClaim:   "Can claim a direct token opportunity only when HO-Azure can show the compute-side token path, the attached identity, and the stronger Azure control behind that identity. Cannot claim SSRF, runtime compromise, metadata abuse, token minting success, or broader credential, deployment, or trust stories without a clearer compute-side transform.",
		CurrentGap:     "The live family is intentionally narrow in v1: direct token-opportunity rows only. Broader trust expansion and secret-bearing config starts still sit outside this family, mixed-identity workloads still need explicit corroboration before default admission, and HO-Azure stays on the recon side of the boundary rather than trying to verify web-app exploitation or other runtime execution paths.",
		BestCurrentExamples: []string{
			"tokens-credentials -> managed-identities -> permissions",
			"tokens-credentials -> env-vars -> managed-identities -> permissions",
		},
		BackingCommands:    []string{"tokens-credentials", "env-vars", "workloads", "managed-identities", "permissions"},
		PreferredArtifacts: []string{"loot", "json"},
		StructuredRowFields: []string{
			"compute_foothold",
			"token_path",
			"identity",
			"azure_access",
			"proof_status",
			"note",
			"confidence_boundary",
			"missing_confirmation",
			"next_review",
			"summary",
		},
		OperatorQuestion: "Which compute surface offers the strongest current control lead without overstating what the evidence proves?",
		SourceCommandMinimum: []FamilySourceContract{
			{Command: "tokens-credentials", MinimumFields: []string{"asset_id", "asset_name", "surface_type", "access_path", "priority", "operator_signal"}, Rationale: "Provides the token-capable compute foothold when a workload can already mint or request tokens."},
			{Command: "env-vars", MinimumFields: []string{"asset_id", "asset_name", "setting_name", "value_type", "key_vault_reference_identity", "workload_identity_ids"}, Rationale: "Provides workload configuration clues that can explicitly name which attached identity a mixed-identity web workload is using."},
			{Command: "workloads", MinimumFields: []string{"asset_id", "asset_name", "asset_kind", "identity_ids", "identity_principal_id", "endpoints"}, Rationale: "Provides the compute-anchor context that explains why the foothold should interrupt broader collection."},
			{Command: "managed-identities", MinimumFields: []string{"id", "name", "identity_type", "principal_id", "attached_to", "scope_ids"}, Rationale: "Provides the explicit attached-identity anchor when HO-Azure can name it cleanly from current scope."},
			{Command: "permissions", MinimumFields: []string{"principal_id", "high_impact_roles", "all_role_names", "scope_ids", "privileged"}, Rationale: "Provides the stronger Azure control visible behind the attached identity."},
		},
	},
}

func Family(name string) (FamilyContract, bool) {
	contract, ok := familyContracts[name]
	return contract, ok
}

func FamilyNames() []string {
	names := make([]string, 0, len(familyContracts))
	for name := range familyContracts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
