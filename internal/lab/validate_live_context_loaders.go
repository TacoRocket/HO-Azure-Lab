package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func loadLiveAzureContext(payloadPath string) (*liveAzureContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-azure-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live Azure context path %q is a directory", contextPath)
	}
	artifact := liveAzureContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveManagedIdentitiesContext(payloadPath string) (*liveManagedIdentitiesContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-managed-identities-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live managed identities context path %q is a directory", contextPath)
	}
	artifact := liveManagedIdentitiesContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveWorkloadsContext(payloadPath string) (*liveWorkloadsContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-workloads-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live workloads context path %q is a directory", contextPath)
	}
	artifact := liveWorkloadsContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveAppServicesContext(payloadPath string) (*liveAppServicesContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-app-services-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live app services context path %q is a directory", contextPath)
	}
	artifact := liveAppServicesContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveFunctionsContext(payloadPath string) (*liveFunctionsContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-functions-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live functions context path %q is a directory", contextPath)
	}
	artifact := liveFunctionsContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveDNSContext(payloadPath string) (*liveDNSContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-dns-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live dns context path %q is a directory", contextPath)
	}
	artifact := liveDNSContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveEndpointsContext(payloadPath string) (*liveEndpointsContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-endpoints-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live endpoints context path %q is a directory", contextPath)
	}
	artifact := liveEndpointsContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveContainerAppsContext(payloadPath string) (*liveContainerAppsContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-container-apps-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live container apps context path %q is a directory", contextPath)
	}
	artifact := liveContainerAppsContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveContainerInstancesContext(payloadPath string) (*liveContainerInstancesContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-container-instances-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live container instances context path %q is a directory", contextPath)
	}
	artifact := liveContainerInstancesContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveLogicAppsContext(payloadPath string) (*liveLogicAppsContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-logic-apps-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live logic apps context path %q is a directory", contextPath)
	}
	artifact := liveLogicAppsContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveAutomationContext(payloadPath string) (*liveAutomationContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-automation-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live automation context path %q is a directory", contextPath)
	}
	artifact := liveAutomationContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveApplicationGatewayContext(payloadPath string) (*liveApplicationGatewayContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-application-gateway-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live application-gateway context path %q is a directory", contextPath)
	}
	artifact := liveApplicationGatewayContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveAPIMgmtContext(payloadPath string) (*liveAPIMgmtContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-api-mgmt-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live api-mgmt context path %q is a directory", contextPath)
	}
	artifact := liveAPIMgmtContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveDatabasesContext(payloadPath string) (*liveDatabasesContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-databases-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live databases context path %q is a directory", contextPath)
	}
	artifact := liveDatabasesContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveStorageContext(payloadPath string) (*liveStorageContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-storage-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live storage context path %q is a directory", contextPath)
	}
	artifact := liveStorageContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveAzureMLContext(payloadPath string) (*liveAzureMLContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-azure-ml-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live azure-ml context path %q is a directory", contextPath)
	}
	artifact := liveAzureMLContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveEventGridContext(payloadPath string) (*liveEventGridContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-event-grid-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live event-grid context path %q is a directory", contextPath)
	}
	artifact := liveEventGridContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveSnapshotsDisksContext(payloadPath string) (*liveSnapshotsDisksContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-snapshots-disks-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live snapshots-disks context path %q is a directory", contextPath)
	}
	artifact := liveSnapshotsDisksContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveNICContext(payloadPath string) (*liveNICContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-nics-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live nics context path %q is a directory", contextPath)
	}
	artifact := liveNICContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveVMSContext(payloadPath string) (*liveVMSContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-vms-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live vms context path %q is a directory", contextPath)
	}
	artifact := liveVMSContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveVMSSContext(payloadPath string) (*liveVMSSContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-vmss-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live vmss context path %q is a directory", contextPath)
	}
	artifact := liveVMSSContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveACRContext(payloadPath string) (*liveACRContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-acr-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live acr context path %q is a directory", contextPath)
	}
	artifact := liveACRContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveAKSContext(payloadPath string) (*liveAKSContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-aks-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live aks context path %q is a directory", contextPath)
	}
	artifact := liveAKSContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveNetworkEffectiveContext(payloadPath string) (*liveNetworkEffectiveContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-network-effective-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live network-effective context path %q is a directory", contextPath)
	}
	artifact := liveNetworkEffectiveContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

func loadLiveNetworkPortsContext(payloadPath string) (*liveNetworkPortsContextArtifact, error) {
	contextPath := filepath.Join(filepath.Dir(payloadPath), "live-network-ports-context.json")
	info, err := os.Stat(contextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("live network-ports context path %q is a directory", contextPath)
	}
	artifact := liveNetworkPortsContextArtifact{}
	if err := LoadJSON(contextPath, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}
