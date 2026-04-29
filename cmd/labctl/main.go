package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ho-azure-lab/internal/lab"
)

func defaultHOAzureDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "../HO-Azure"
	}
	return filepath.Join(cwd, "..", "HO-Azure")
}

func defaultInfraDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "infra"
	}
	return filepath.Join(cwd, "infra")
}

func writeOutput(path string, payload any, text string) error {
	if path == "" {
		if text != "" {
			fmt.Print(text)
			return nil
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", data)
		return nil
	}
	if text != "" {
		return os.WriteFile(path, []byte(text), 0o644)
	}
	return lab.WriteJSON(path, payload)
}

func mergeSelectorString(existing string, additions []string) string {
	joined := strings.Join(additions, ",")
	if joined == "" {
		return existing
	}
	if strings.TrimSpace(existing) == "" {
		return joined
	}
	return existing + "," + joined
}

func applyRunProfileFile(profileFile string, runProfile, commandSelectors, familySelectors, viewpoint *string) error {
	if strings.TrimSpace(profileFile) == "" {
		return nil
	}
	definition, err := lab.LoadRunProfileDefinition(profileFile)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*runProfile) == "" {
		*runProfile = definition.Profile
	}
	*commandSelectors = mergeSelectorString(*commandSelectors, definition.Commands)
	*familySelectors = mergeSelectorString(*familySelectors, definition.Families)
	if strings.TrimSpace(definition.Viewpoint) != "" && *viewpoint == "all" {
		*viewpoint = definition.Viewpoint
	}
	return nil
}

func main() {
	os.Exit(run())
}

func extractProviderArgs(args []string, defaultProvider string) (string, []string, error) {
	provider := defaultProvider
	forwarded := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--provider" {
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("--provider requires a value")
			}
			provider = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--provider=") {
			provider = strings.TrimPrefix(arg, "--provider=")
			continue
		}
		forwarded = append(forwarded, arg)
	}
	return provider, forwarded, nil
}

func runSetupAzureCommand(args []string) int {
	fs := flag.NewFlagSet("setup-azure-environment", flag.ExitOnError)
	infraDir := fs.String("infra-dir", defaultInfraDir(), "Path to the infra directory.")
	output := fs.String("output", "", "Optional generated tfvars output path.")
	location := fs.String("location", "centralus", "Azure region for the lab.")
	namePrefix := fs.String("name-prefix", "hoazurelab", "Short prefix used in lab resource names.")
	sshPublicKey := fs.String("ssh-public-key", "", "Inline SSH public key.")
	sshPublicKeyFile := fs.String("ssh-public-key-file", "", "Path to the SSH public key file.")
	costProfile := fs.String("cost-profile", "default", "Compute cost profile: default or lower-cost.")
	aksVMSize := fs.String("aks-vm-size", "Standard_D2s_v3", "AKS VM size.")
	enableDefaultFollowUps := fs.Bool("enable-default-followups", false, "Enable the default follow-up bundle: API Management, AKS, and WAF/Application Gateway. This is implicit for cost-profile=default and explicit for lower-cost.")
	enableAzureML := fs.Bool("enable-azure-ml", false, "Enable the separate Azure ML OpenTofu lane.")
	enableDeploymentPathAddin := fs.Bool("enable-deployment-path-addin", false, "Enable the separate deployment-path proof add-in lane.")
	enableResourceHijackingAddin := fs.Bool("enable-resource-hijacking-addin", false, "Enable the separate resource-hijacking proof add-in lane.")
	enableExfilAddin := fs.Bool("enable-exfil-addin", false, "Enable the separate exfil proof add-in lane.")
	enableComputeControlAddin := fs.Bool("enable-compute-control-addin", false, "Enable the separate compute-control proof add-in lane.")
	enablePersistenceAddin := fs.Bool("enable-persistence-addin", false, "Enable the separate persistence proof add-in lane.")
	enableHumanUserViewpoints := fs.Bool("enable-human-user-viewpoints", false, "Best-effort second-phase creation of lab human-user viewpoints.")
	humanUserOutput := fs.String("human-user-output", "", "Optional output path for generated human-user viewpoint credentials.")
	writeOnly := fs.Bool("write-only", false, "Only write the generated tfvars file and skip tofu init/apply.")
	_ = fs.Parse(args)

	_, returnCode, err := lab.RunAzureSetup(lab.AzureSetupConfig{
		InfraDir:                      *infraDir,
		OutputPath:                    *output,
		Location:                      *location,
		NamePrefix:                    *namePrefix,
		SSHPublicKey:                  *sshPublicKey,
		SSHPublicKeyFile:              *sshPublicKeyFile,
		CostProfile:                   *costProfile,
		AKSVMSize:                     *aksVMSize,
		EnableRoleTrustsCanary:        true,
		EnableDeploymentHistoryCanary: true,
		EnableDefaultFollowUps:        *enableDefaultFollowUps,
		EnableAzureML:                 *enableAzureML,
		EnableDeploymentPathAddin:     *enableDeploymentPathAddin,
		EnableResourceHijackingAddin:  *enableResourceHijackingAddin,
		EnableExfilAddin:              *enableExfilAddin,
		EnableComputeControlAddin:     *enableComputeControlAddin,
		EnablePersistenceAddin:        *enablePersistenceAddin,
		EnableHumanUserViewpoints:     *enableHumanUserViewpoints,
		HumanUserOutputPath:           *humanUserOutput,
		WriteOnly:                     *writeOnly,
		ProgressWriter:                os.Stdout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return returnCode
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labctl <derive-surface|scaffold-manifest|scaffold-run|validate|live-validate-run|run-azure-execution|run-azure-validation|run-validation|setup-azure-environment|setup-environment>")
		return 2
	}

	switch os.Args[1] {
	case "derive-surface":
		fs := flag.NewFlagSet("derive-surface", flag.ExitOnError)
		hoAzureDir := fs.String("ho-azure-dir", defaultHOAzureDir(), "Path to the HO-Azure repo.")
		output := fs.String("output", "", "Optional output file. Defaults to stdout.")
		_ = fs.Parse(os.Args[2:])

		payload, err := lab.DeriveSurface(*hoAzureDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := writeOutput(*output, payload, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0

	case "scaffold-manifest":
		fs := flag.NewFlagSet("scaffold-manifest", flag.ExitOnError)
		hoAzureDir := fs.String("ho-azure-dir", defaultHOAzureDir(), "Path to the HO-Azure repo.")
		profile := fs.String("profile", "uniform", "Manifest scaffold profile.")
		defaultStatus := fs.String("default-status", "excepted", "Default surface status for uniform profile.")
		reasonCode := fs.String("reason-code", "bootstrap_pending", "Reason code for non-covered uniform entries.")
		output := fs.String("output", "", "Output file path.")
		_ = fs.Parse(os.Args[2:])
		if *output == "" {
			fmt.Fprintln(os.Stderr, "--output is required")
			return 2
		}

		payload, err := lab.ScaffoldManifest(*hoAzureDir, *defaultStatus, *reasonCode, *profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := lab.WriteJSON(*output, payload); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0

	case "scaffold-run":
		fs := flag.NewFlagSet("scaffold-run", flag.ExitOnError)
		manifestPath := fs.String("manifest", "", "Path to the manifest JSON file.")
		outputDir := fs.String("output-dir", "", "Directory for the run scaffold.")
		runID := fs.String("run-id", "bootstrap-run", "Run identifier.")
		demoCaptureExpected := fs.Bool("demo-capture-expected", false, "Mark the scaffold as expecting demo capture artifacts.")
		_ = fs.Parse(os.Args[2:])
		if *manifestPath == "" || *outputDir == "" {
			fmt.Fprintln(os.Stderr, "--manifest and --output-dir are required")
			return 2
		}
		manifest := lab.Manifest{}
		if err := lab.LoadJSON(*manifestPath, &manifest); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		runResult, err := lab.ScaffoldRun(manifest, *outputDir, *runID, *demoCaptureExpected)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := lab.WriteJSON(filepath.Join(*outputDir, "run-result.json"), runResult); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0

	case "validate":
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		manifestPath := fs.String("manifest", "", "Path to the manifest JSON file.")
		runResults := fs.String("run-results", "", "Optional run-result JSON path.")
		hoAzureDir := fs.String("ho-azure-dir", defaultHOAzureDir(), "Path to the HO-Azure repo.")
		output := fs.String("output", "", "Optional output file. Defaults to stdout.")
		format := fs.String("format", "json", "Render format: json or text.")
		_ = fs.Parse(os.Args[2:])
		if *manifestPath == "" {
			fmt.Fprintln(os.Stderr, "--manifest is required")
			return 2
		}

		payload, err := lab.ValidateLab(*manifestPath, *hoAzureDir, *runResults)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		text := ""
		if *format == "text" {
			text = lab.RenderText(payload)
		}
		if err := writeOutput(*output, payload, text); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0

	case "live-validate-run":
		fs := flag.NewFlagSet("live-validate-run", flag.ExitOnError)
		runResultsPath := fs.String("run-results", "", "Path to run-result.json.")
		hoAzureDir := fs.String("ho-azure-dir", defaultHOAzureDir(), "Path to the HO-Azure repo.")
		output := fs.String("output", "", "Optional output path. Defaults beside run-result.json.")
		writeRunResults := fs.Bool("write-run-results", false, "Write findings back into run-result.json.")
		_ = fs.Parse(os.Args[2:])
		if *runResultsPath == "" {
			fmt.Fprintln(os.Stderr, "--run-results is required")
			return 2
		}

		summary, err := lab.ValidateLiveRun(*runResultsPath, *hoAzureDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		exitCode, err := lab.SaveLiveValidationSummary(*runResultsPath, *output, summary, *writeRunResults)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return exitCode

	case "run-azure-execution":
		fs := flag.NewFlagSet("run-azure-execution", flag.ExitOnError)
		manifestPath := fs.String("manifest", "", "Path to the manifest JSON file.")
		outputDir := fs.String("output-dir", "", "Directory where the run artifacts should be written.")
		hoAzureDir := fs.String("ho-azure-dir", defaultHOAzureDir(), "Path to the HO-Azure repo.")
		infraDir := fs.String("infra-dir", defaultInfraDir(), "Path to the lab infra directory for loading lab outputs.")
		toolBin := fs.String("tool-bin", "", "Optional path to a built HO-Azure binary. If omitted, labctl builds one from the HO-Azure source tree first.")
		runID := fs.String("run-id", "live-validation-run", "Run identifier.")
		runProfile := fs.String("profile", "", "Run profile label. Defaults to release-candidate unless surface or viewpoint selectors narrow the run.")
		runProfileFile := fs.String("profile-file", "", "Optional JSON file containing a reusable run profile definition.")
		commandSelectors := fs.String("commands", "", "Comma-separated manifest commands to execute after manifest/viewpoint admission.")
		familySelectors := fs.String("families", "", "Comma-separated manifest families to execute after manifest/viewpoint admission.")
		viewpoint := fs.String("viewpoint", "all", "Viewpoint lane to execute.")
		viewpointCredentials := fs.String("viewpoint-credentials", "", "Optional JSON file for reduced viewpoints.")
		tenant := fs.String("tenant", "", "Optional Azure tenant ID.")
		subscription := fs.String("subscription", "", "Optional Azure subscription ID.")
		devopsOrganization := fs.String("devops-organization", "", "Optional Azure DevOps organization.")
		commandTimeoutSeconds := fs.Int("command-timeout-seconds", 600, "Per-command timeout in seconds. Use 0 to disable the timeout.")
		commandInactivitySeconds := fs.Int("command-inactivity-seconds", 120, "Fail a command if it produces no output or artifact updates for this many seconds. Use 0 to disable the inactivity timeout.")
		slowCommandSeconds := fs.Int("slow-command-seconds", 180, "Flag a command as a performance issue if it completes slower than this many seconds. Use 0 to disable the slow-command threshold.")
		demoCaptureExpected := fs.Bool("demo-capture-expected", false, "Mark the run as expecting demo capture artifacts.")
		_ = fs.Parse(os.Args[2:])
		if *manifestPath == "" || *outputDir == "" {
			fmt.Fprintln(os.Stderr, "--manifest and --output-dir are required")
			return 2
		}
		if err := applyRunProfileFile(*runProfileFile, runProfile, commandSelectors, familySelectors, viewpoint); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		returnCode, err := lab.RunAzureValidation(lab.AzureRunConfig{
			ManifestPath:             *manifestPath,
			OutputDir:                *outputDir,
			HOAzureDir:               *hoAzureDir,
			InfraDir:                 *infraDir,
			ToolBin:                  *toolBin,
			RunID:                    *runID,
			RunProfile:               *runProfile,
			CommandSelectors:         []string{*commandSelectors},
			FamilySelectors:          []string{*familySelectors},
			Viewpoint:                *viewpoint,
			ViewpointCredentials:     *viewpointCredentials,
			Tenant:                   *tenant,
			Subscription:             *subscription,
			DevOpsOrganization:       *devopsOrganization,
			CommandTimeout:           time.Duration(*commandTimeoutSeconds) * time.Second,
			CommandInactivityTimeout: time.Duration(*commandInactivitySeconds) * time.Second,
			CommandSlowThreshold:     time.Duration(*slowCommandSeconds) * time.Second,
			DemoCaptureExpected:      *demoCaptureExpected,
			ProgressWriter:           os.Stdout,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return returnCode

	case "run-azure-validation":
		fs := flag.NewFlagSet("run-azure-validation", flag.ExitOnError)
		manifestPath := fs.String("manifest", "", "Path to the manifest JSON file.")
		outputDir := fs.String("output-dir", "", "Directory where the run artifacts should be written.")
		hoAzureDir := fs.String("ho-azure-dir", defaultHOAzureDir(), "Path to the HO-Azure repo.")
		infraDir := fs.String("infra-dir", defaultInfraDir(), "Path to the lab infra directory for loading lab outputs.")
		toolBin := fs.String("tool-bin", "", "Optional path to a built HO-Azure binary. If omitted, labctl builds one from the HO-Azure source tree first.")
		runID := fs.String("run-id", "live-validation-run", "Run identifier.")
		runProfile := fs.String("profile", "", "Run profile label. Defaults to release-candidate unless surface or viewpoint selectors narrow the run.")
		runProfileFile := fs.String("profile-file", "", "Optional JSON file containing a reusable run profile definition.")
		commandSelectors := fs.String("commands", "", "Comma-separated manifest commands to execute after manifest/viewpoint admission.")
		familySelectors := fs.String("families", "", "Comma-separated manifest families to execute after manifest/viewpoint admission.")
		viewpoint := fs.String("viewpoint", "all", "Viewpoint lane to execute.")
		viewpointCredentials := fs.String("viewpoint-credentials", "", "Optional JSON file for reduced viewpoints.")
		tenant := fs.String("tenant", "", "Optional Azure tenant ID.")
		subscription := fs.String("subscription", "", "Optional Azure subscription ID.")
		devopsOrganization := fs.String("devops-organization", "", "Optional Azure DevOps organization.")
		commandTimeoutSeconds := fs.Int("command-timeout-seconds", 600, "Per-command timeout in seconds. Use 0 to disable the timeout.")
		commandInactivitySeconds := fs.Int("command-inactivity-seconds", 120, "Fail a command if it produces no output or artifact updates for this many seconds. Use 0 to disable the inactivity timeout.")
		slowCommandSeconds := fs.Int("slow-command-seconds", 180, "Flag a command as a performance issue if it completes slower than this many seconds. Use 0 to disable the slow-command threshold.")
		demoCaptureExpected := fs.Bool("demo-capture-expected", false, "Mark the run as expecting demo capture artifacts.")
		_ = fs.Parse(os.Args[2:])
		if *manifestPath == "" || *outputDir == "" {
			fmt.Fprintln(os.Stderr, "--manifest and --output-dir are required")
			return 2
		}
		if err := applyRunProfileFile(*runProfileFile, runProfile, commandSelectors, familySelectors, viewpoint); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		returnCode, err := lab.RunValidation(lab.AzureRunConfig{
			ManifestPath:             *manifestPath,
			OutputDir:                *outputDir,
			HOAzureDir:               *hoAzureDir,
			InfraDir:                 *infraDir,
			ToolBin:                  *toolBin,
			RunID:                    *runID,
			RunProfile:               *runProfile,
			CommandSelectors:         []string{*commandSelectors},
			FamilySelectors:          []string{*familySelectors},
			Viewpoint:                *viewpoint,
			ViewpointCredentials:     *viewpointCredentials,
			Tenant:                   *tenant,
			Subscription:             *subscription,
			DevOpsOrganization:       *devopsOrganization,
			CommandTimeout:           time.Duration(*commandTimeoutSeconds) * time.Second,
			CommandInactivityTimeout: time.Duration(*commandInactivitySeconds) * time.Second,
			CommandSlowThreshold:     time.Duration(*slowCommandSeconds) * time.Second,
			DemoCaptureExpected:      *demoCaptureExpected,
			ProgressWriter:           os.Stdout,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return returnCode

	case "run-validation":
		fs := flag.NewFlagSet("run-validation", flag.ExitOnError)
		provider := fs.String("provider", "azure", "Cloud slice to run.")
		manifestPath := fs.String("manifest", "", "Path to the manifest JSON file.")
		outputDir := fs.String("output-dir", "", "Directory where the run artifacts should be written.")
		hoAzureDir := fs.String("ho-azure-dir", defaultHOAzureDir(), "Path to the HO-Azure repo.")
		infraDir := fs.String("infra-dir", defaultInfraDir(), "Path to the lab infra directory for loading lab outputs.")
		toolBin := fs.String("tool-bin", "", "Optional path to a built HO-Azure binary. If omitted, labctl builds one from the HO-Azure source tree first.")
		runID := fs.String("run-id", "live-validation-run", "Run identifier.")
		runProfile := fs.String("profile", "", "Run profile label. Defaults to release-candidate unless surface or viewpoint selectors narrow the run.")
		runProfileFile := fs.String("profile-file", "", "Optional JSON file containing a reusable run profile definition.")
		commandSelectors := fs.String("commands", "", "Comma-separated manifest commands to execute after manifest/viewpoint admission.")
		familySelectors := fs.String("families", "", "Comma-separated manifest families to execute after manifest/viewpoint admission.")
		viewpoint := fs.String("viewpoint", "all", "Viewpoint lane to execute.")
		viewpointCredentials := fs.String("viewpoint-credentials", "", "Optional JSON file for reduced viewpoints.")
		tenant := fs.String("tenant", "", "Optional Azure tenant ID.")
		subscription := fs.String("subscription", "", "Optional Azure subscription ID.")
		devopsOrganization := fs.String("devops-organization", "", "Optional Azure DevOps organization.")
		commandTimeoutSeconds := fs.Int("command-timeout-seconds", 600, "Per-command timeout in seconds. Use 0 to disable the timeout.")
		commandInactivitySeconds := fs.Int("command-inactivity-seconds", 120, "Fail a command if it produces no output or artifact updates for this many seconds. Use 0 to disable the inactivity timeout.")
		slowCommandSeconds := fs.Int("slow-command-seconds", 180, "Flag a command as a performance issue if it completes slower than this many seconds. Use 0 to disable the slow-command threshold.")
		demoCaptureExpected := fs.Bool("demo-capture-expected", false, "Mark the run as expecting demo capture artifacts.")
		_ = fs.Parse(os.Args[2:])
		if *provider != "azure" {
			fmt.Fprintln(os.Stderr, "unsupported provider: "+*provider)
			return 2
		}
		if err := applyRunProfileFile(*runProfileFile, runProfile, commandSelectors, familySelectors, viewpoint); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		returnCode, err := lab.RunValidation(lab.AzureRunConfig{
			ManifestPath:             *manifestPath,
			OutputDir:                *outputDir,
			HOAzureDir:               *hoAzureDir,
			InfraDir:                 *infraDir,
			ToolBin:                  *toolBin,
			RunID:                    *runID,
			RunProfile:               *runProfile,
			CommandSelectors:         []string{*commandSelectors},
			FamilySelectors:          []string{*familySelectors},
			Viewpoint:                *viewpoint,
			ViewpointCredentials:     *viewpointCredentials,
			Tenant:                   *tenant,
			Subscription:             *subscription,
			DevOpsOrganization:       *devopsOrganization,
			CommandTimeout:           time.Duration(*commandTimeoutSeconds) * time.Second,
			CommandInactivityTimeout: time.Duration(*commandInactivitySeconds) * time.Second,
			CommandSlowThreshold:     time.Duration(*slowCommandSeconds) * time.Second,
			DemoCaptureExpected:      *demoCaptureExpected,
			ProgressWriter:           os.Stdout,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return returnCode

	case "setup-azure-environment":
		return runSetupAzureCommand(os.Args[2:])

	case "setup-environment":
		provider, forwardedArgs, err := extractProviderArgs(os.Args[2:], "azure")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if provider != "azure" {
			fmt.Fprintln(os.Stderr, "unsupported provider: "+provider)
			return 2
		}
		return runSetupAzureCommand(forwardedArgs)
	}

	fmt.Fprintln(os.Stderr, "unknown subcommand: "+os.Args[1])
	return 2
}
