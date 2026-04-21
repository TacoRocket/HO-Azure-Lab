package contracts

import "sort"

type CommandContract struct {
	Name             string
	Section          string
	Status           string
	Model            string
	OperatorQuestion string
	TopLevelFields   []string
	Flags            []CommandFlag
}

type CommandFlag struct {
	Name  string
	Usage string
}

var commandContracts = map[string]CommandContract{
	"whoami": {
		Name:             "whoami",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "WhoAmIOutput",
		OperatorQuestion: "Who am I in this tenant and what subscription scope am I operating in right now?",
		TopLevelFields: []string{
			"tenant_id",
			"subscription",
			"principal",
			"effective_scopes",
			"issues",
			"metadata",
		},
	},
	"inventory": {
		Name:             "inventory",
		Section:          "core",
		Status:           StatusImplemented,
		Model:            "InventoryOutput",
		OperatorQuestion: "What cloud infrastructure and service surface is visible in this subscription?",
		TopLevelFields: []string{
			"issues",
			"metadata",
			"resource_count",
			"resource_group_count",
			"subscription",
			"top_resource_types",
		},
	},
	"automation": {
		Name:             "automation",
		Section:          "resource",
		Status:           StatusImplemented,
		Model:            "AutomationOutput",
		OperatorQuestion: "Which Azure Automation accounts expose the strongest identity, execution, trigger, worker, and secure-asset cues for operator follow-up?",
		TopLevelFields: []string{
			"metadata",
			"automation_accounts",
			"findings",
			"issues",
		},
	},
	"devops": {
		Name:             "devops",
		Section:          "resource",
		Status:           StatusImplemented,
		Model:            "DevopsOutput",
		OperatorQuestion: "Which Azure DevOps build definitions expose the strongest trusted-input, execution, Azure-control, and target cues for operator follow-up?",
		TopLevelFields: []string{
			"metadata",
			"pipelines",
			"findings",
			"issues",
		},
		Flags: []CommandFlag{
			{Name: "devops-organization", Usage: "Azure DevOps organization"},
		},
	},
	"app-services": {
		Name:             "app-services",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "AppServicesOutput",
		OperatorQuestion: "Which App Service apps expose the strongest runtime, identity, and ingress cues for operator follow-up?",
		TopLevelFields: []string{
			"app_services",
			"findings",
			"issues",
			"metadata",
		},
	},
	"acr": {
		Name:             "acr",
		Section:          "resource",
		Status:           StatusImplemented,
		Model:            "AcrOutput",
		OperatorQuestion: "Which container registries expose the strongest login, auth, network, and automation trust cues for operator follow-up?",
		TopLevelFields: []string{
			"registries",
			"findings",
			"issues",
			"metadata",
		},
	},
	"databases": {
		Name:             "databases",
		Section:          "resource",
		Status:           StatusImplemented,
		Model:            "DatabasesOutput",
		OperatorQuestion: "Which relational database servers expose the strongest public, identity, and posture cues for operator follow-up?",
		TopLevelFields: []string{
			"database_servers",
			"findings",
			"issues",
			"metadata",
		},
	},
	"dns": {
		Name:             "dns",
		Section:          "network",
		Status:           StatusImplemented,
		Model:            "DnsOutput",
		OperatorQuestion: "Which public and private DNS zones expose the most useful namespace, delegation, and private-endpoint boundary cues for operator follow-up?",
		TopLevelFields: []string{
			"dns_zones",
			"findings",
			"issues",
			"metadata",
		},
	},
	"application-gateway": {
		Name:             "application-gateway",
		Section:          "network",
		Status:           StatusImplemented,
		Model:            "ApplicationGatewayOutput",
		OperatorQuestion: "Which Application Gateways expose the strongest public edge, shared routing breadth, backend fan-out, and WAF posture cues for operator follow-up?",
		TopLevelFields: []string{
			"application_gateways",
			"findings",
			"issues",
			"metadata",
		},
	},
	"functions": {
		Name:             "functions",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "FunctionsOutput",
		OperatorQuestion: "Which Function Apps expose the most interesting runtime, identity, storage, and ingress posture for operator follow-up?",
		TopLevelFields: []string{
			"findings",
			"function_apps",
			"issues",
			"metadata",
		},
	},
	"azure-ml": {
		Name:             "azure-ml",
		Section:          "workflow",
		Status:           StatusImplemented,
		Model:            "AzureMLOutput",
		OperatorQuestion: "Which Azure ML workspaces already show execution-capable runtime surfaces versus only supporting context from the current control-plane read path?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"workspaces",
		},
	},
	"event-grid": {
		Name:             "event-grid",
		Section:          "workflow",
		Status:           StatusImplemented,
		Model:            "EventGridOutput",
		OperatorQuestion: "What visible Event Grid routes already exist, and which destinations look execution-capable versus only supporting context?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"routes",
		},
	},
	"logic-apps": {
		Name:             "logic-apps",
		Section:          "workflow",
		Status:           StatusImplemented,
		Model:            "LogicAppsOutput",
		OperatorQuestion: "Which Logic Apps are triggerable, identity-bearing, and operationally meaningful enough to inspect first?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"workflows",
		},
	},
	"container-apps": {
		Name:             "container-apps",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "ContainerAppsOutput",
		OperatorQuestion: "Which Container Apps are externally reachable, and which of them carry the identity context worth deeper operator follow-up?",
		TopLevelFields: []string{
			"container_apps",
			"findings",
			"issues",
			"metadata",
		},
	},
	"container-instances": {
		Name:             "container-instances",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "ContainerInstancesOutput",
		OperatorQuestion: "Which container groups are publicly reachable, and which of them carry the identity or runtime posture worth deeper operator follow-up?",
		TopLevelFields: []string{
			"container_instances",
			"findings",
			"issues",
			"metadata",
		},
	},
	"aks": {
		Name:             "aks",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "AksOutput",
		OperatorQuestion: "Which AKS clusters expose the most meaningful control-plane, identity, auth, and Azure-side federation cues for operator follow-up?",
		TopLevelFields: []string{
			"aks_clusters",
			"findings",
			"issues",
			"metadata",
		},
	},
	"api-mgmt": {
		Name:             "api-mgmt",
		Section:          "resource",
		Status:           StatusImplemented,
		Model:            "ApiMgmtOutput",
		OperatorQuestion: "Which API Management services expose the most meaningful gateway, identity, subscription, backend, and secret posture for operator follow-up?",
		TopLevelFields: []string{
			"api_management_services",
			"findings",
			"issues",
			"metadata",
		},
	},
	"app-credentials": {
		Name:             "app-credentials",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "AppCredentialsOutput",
		OperatorQuestion: "Which applications or service principals already carry authentication material or federated trust, and where does the current identity already have a visible path to change that material?",
		TopLevelFields: []string{
			"app_credentials",
			"issues",
			"metadata",
		},
	},
	"arm-deployments": {
		Name:             "arm-deployments",
		Section:          "config",
		Status:           StatusImplemented,
		Model:            "ArmDeploymentsOutput",
		OperatorQuestion: "Which ARM deployments reveal useful config context, linked templates, or output values worth operator review?",
		TopLevelFields: []string{
			"deployments",
			"findings",
			"issues",
			"metadata",
		},
	},
	"endpoints": {
		Name:             "endpoints",
		Section:          "network",
		Status:           StatusImplemented,
		Model:            "EndpointsOutput",
		OperatorQuestion: "Which IPs or hostnames should I triage first, and which assets do those ingress paths belong to?",
		TopLevelFields: []string{
			"endpoints",
			"findings",
			"issues",
			"metadata",
		},
	},
	"network-effective": {
		Name:             "network-effective",
		Section:          "network",
		Status:           StatusImplemented,
		Model:            "NetworkEffectiveOutput",
		OperatorQuestion: "Which public-IP-backed assets look most worth investigating first once I combine visible endpoint and inbound-rule evidence?",
		TopLevelFields: []string{
			"effective_exposures",
			"findings",
			"issues",
			"metadata",
		},
	},
	"network-ports": {
		Name:             "network-ports",
		Section:          "network",
		Status:           StatusImplemented,
		Model:            "NetworkPortsOutput",
		OperatorQuestion: "Which visible public endpoints also have NSG evidence that suggests inbound port reachability, and where does that allow appear to come from?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"network_ports",
		},
	},
	"env-vars": {
		Name:             "env-vars",
		Section:          "config",
		Status:           StatusImplemented,
		Model:            "EnvVarsOutput",
		OperatorQuestion: "Which App Service or Function App settings look like direct secret material, and which ones point toward Key Vault or identity-backed follow-on?",
		TopLevelFields: []string{
			"env_vars",
			"findings",
			"issues",
			"metadata",
		},
	},
	"tokens-credentials": {
		Name:             "tokens-credentials",
		Section:          "secrets",
		Status:           StatusImplemented,
		Model:            "TokensCredentialsOutput",
		OperatorQuestion: "Which workloads can mint tokens or expose credential-bearing metadata paths worth operator follow-up first, and what should I pivot to next?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"surfaces",
		},
	},
	"rbac": {
		Name:             "rbac",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "RbacOutput",
		OperatorQuestion: "Which principals have role assignments here, and at what scopes?",
		TopLevelFields: []string{
			"metadata",
			"principals",
			"scopes",
			"role_assignments",
			"issues",
		},
	},
	"principals": {
		Name:             "principals",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "PrincipalsOutput",
		OperatorQuestion: "Which principals are visible from the current Azure read path, what role and identity context do they carry, and which one is the current identity?",
		TopLevelFields: []string{
			"issues",
			"metadata",
			"principals",
		},
	},
	"permissions": {
		Name:             "permissions",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "PermissionsOutput",
		OperatorQuestion: "Which principals already show direct Azure control, and what should the operator review next?",
		TopLevelFields: []string{
			"metadata",
			"permissions",
			"issues",
		},
	},
	"privesc": {
		Name:             "privesc",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "PrivescOutput",
		OperatorQuestion: "Which privilege-escalation or workload-identity abuse leads are already visible from the current Azure read path?",
		TopLevelFields: []string{
			"issues",
			"metadata",
			"paths",
		},
	},
	"role-trusts": {
		Name:             "role-trusts",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "RoleTrustsOutput",
		OperatorQuestion: "Which ownership, federation, or app-trust relationships could let one identity influence another?",
		TopLevelFields: []string{
			"metadata",
			"mode",
			"trusts",
			"issues",
		},
		Flags: []CommandFlag{
			{Name: "mode", Usage: "role-trusts collection mode: fast (default), full, fast-old (deprecated), or full-old (deprecated)"},
		},
	},
	"lighthouse": {
		Name:             "lighthouse",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "LighthouseOutput",
		OperatorQuestion: "Which subscriptions or resource groups are delegated to another tenant through Azure Lighthouse, and which delegations deserve review first?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"lighthouse_delegations",
			"metadata",
		},
	},
	"cross-tenant": {
		Name:             "cross-tenant",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "CrossTenantOutput",
		OperatorQuestion: "Which visible outside-tenant relationships most change who can operate here or how an attacker could pivot into or across this environment?",
		TopLevelFields: []string{
			"cross_tenant_paths",
			"findings",
			"issues",
			"metadata",
		},
	},
	"auth-policies": {
		Name:             "auth-policies",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "AuthPoliciesOutput",
		OperatorQuestion: "Which tenant auth and conditional-access policies are visible, and which ones raise the strongest operator follow-up?",
		TopLevelFields: []string{
			"auth_policies",
			"findings",
			"issues",
			"metadata",
		},
	},
	"managed-identities": {
		Name:             "managed-identities",
		Section:          "identity",
		Status:           StatusImplemented,
		Model:            "ManagedIdentitiesOutput",
		OperatorQuestion: "Which workloads carry managed identities, and which of those identities show the most meaningful workload pivot from current scope?",
		TopLevelFields: []string{
			"metadata",
			"identities",
			"role_assignments",
			"findings",
			"issues",
		},
	},
	"keyvault": {
		Name:             "keyvault",
		Section:          "secrets",
		Status:           StatusImplemented,
		Model:            "KeyVaultOutput",
		OperatorQuestion: "Which Key Vault assets expose the strongest public reachability, access-model weakness, or destructive recovery cues for operator follow-up?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"key_vaults",
			"metadata",
		},
	},
	"resource-trusts": {
		Name:             "resource-trusts",
		Section:          "resource",
		Status:           StatusImplemented,
		Model:            "ResourceTrustsOutput",
		OperatorQuestion: "Which storage and Key Vault assets currently trust public or private network paths strongly enough to matter for operator follow-up?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"resource_trusts",
		},
	},
	"storage": {
		Name:             "storage",
		Section:          "storage",
		Status:           StatusImplemented,
		Model:            "StorageOutput",
		OperatorQuestion: "Which storage assets are likely exposed, and where should I look for accessible data next?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"storage_assets",
		},
	},
	"snapshots-disks": {
		Name:             "snapshots-disks",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "SnapshotsDisksOutput",
		OperatorQuestion: "Which managed disks and snapshots expose the strongest offline-copy, sharing/export, and encryption posture cues for operator follow-up?",
		TopLevelFields: []string{
			"metadata",
			"snapshot_disk_assets",
			"findings",
			"issues",
		},
	},
	"nics": {
		Name:             "nics",
		Section:          "network",
		Status:           StatusImplemented,
		Model:            "NicsOutput",
		OperatorQuestion: "Which NICs anchor workload network placement, public IP references, and basic security-boundary context worth operator review first?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"nic_assets",
		},
	},
	"workloads": {
		Name:             "workloads",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "WorkloadsOutput",
		OperatorQuestion: "Which workloads are worth operator follow-up first once I join identity-bearing assets with their visible endpoint paths?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"workloads",
		},
	},
	"vms": {
		Name:             "vms",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "VmsOutput",
		OperatorQuestion: "Which virtual machines have public IP exposure, and which of them expose useful identity or ingress paths?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"vm_assets",
		},
	},
	"vmss": {
		Name:             "vmss",
		Section:          "compute",
		Status:           StatusImplemented,
		Model:            "VmssOutput",
		OperatorQuestion: "Which scale sets look most worth follow-up once I combine identity, fleet size, and visible frontend network cues?",
		TopLevelFields: []string{
			"findings",
			"issues",
			"metadata",
			"vmss_assets",
		},
	},
	"chains": {
		Name:             "chains",
		Section:          "orchestration",
		Status:           StatusImplemented,
		Model:            "ChainsOutput",
		OperatorQuestion: "Which grouped chain family best answers the next operator decision from current Azure-visible evidence?",
		TopLevelFields: []string{
			"metadata",
			"grouped_command_name",
			"selected_family",
			"families",
			"issues",
		},
	},
	"persistence": {
		Name:             "persistence",
		Section:          "orchestration",
		Status:           StatusImplemented,
		Model:            "PersistenceOutput",
		OperatorQuestion: "Which Azure-native persistence surface should I review first when I want an end-to-end capability story from the current identity?",
		TopLevelFields: []string{
			"metadata",
			"grouped_command_name",
			"selected_surface",
			"surfaces",
			"issues",
		},
	},
}

func placeholderCommand(name string, section string, model string) CommandContract {
	return CommandContract{
		Name:             name,
		Section:          section,
		Status:           StatusPlaceholder,
		Model:            model,
		OperatorQuestion: "Placeholder contract carried forward from AzureFox for faithful migration.",
		TopLevelFields:   []string{"metadata", "issues"},
	}
}

func Command(name string) (CommandContract, bool) {
	contract, ok := commandContracts[name]
	return contract, ok
}

func CommandNames() []string {
	names := make([]string, 0, len(commandContracts))
	for name := range commandContracts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func ImplementedCommands() []CommandContract {
	implemented := []CommandContract{}
	for _, name := range CommandNames() {
		contract := commandContracts[name]
		if contract.Status == StatusImplemented {
			implemented = append(implemented, contract)
		}
	}
	return implemented
}
