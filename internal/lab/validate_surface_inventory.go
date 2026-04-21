package lab

import (
	"fmt"
	"maps"
	"strings"
)

func validateInventoryPayloadAgainstAzureContext(entry CommandLogEntry, label string, payload map[string]any, context *liveInventoryContextArtifact) []Finding {
	if entry.SurfaceKind != "commands" || entry.SurfaceName != "inventory" {
		return nil
	}
	if context == nil {
		return []Finding{makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-live-inventory-context", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" passed but did not record a live inventory context artifact",
			"lab runner inventory context capture",
			"inventory validation should compare the tool payload against recorded Azure subscription and resource inventory truth instead of remembered counts",
		)}
	}

	findings := []Finding{}
	metadata, _ := payload["metadata"].(map[string]any)
	if metadata != nil {
		if tenantID, _ := metadata["tenant_id"].(string); strings.TrimSpace(context.TenantID) != "" && strings.TrimSpace(tenantID) != strings.TrimSpace(context.TenantID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-tenant-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s reported metadata.tenant_id %q, but Azure context reports %q", label, tenantID, context.TenantID),
				"inventory metadata rendering or Azure-backed validation context",
				"inventory should keep tenant identity aligned with the Azure account context it used",
			))
		}
		if subscriptionID, _ := metadata["subscription_id"].(string); strings.TrimSpace(context.Subscription.ID) != "" && strings.TrimSpace(subscriptionID) != strings.TrimSpace(context.Subscription.ID) {
			findings = append(findings, makeBlockingFinding(
				fmt.Sprintf("%s-%s-%s-subscription-id-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
				fmt.Sprintf("%s reported metadata.subscription_id %q, but Azure context reports %q", label, subscriptionID, context.Subscription.ID),
				"inventory metadata rendering or Azure-backed validation context",
				"inventory should keep metadata subscription identity aligned with the Azure account context it used",
			))
		}
	}

	subscription, _ := payload["subscription"].(map[string]any)
	if subscription == nil {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-missing-subscription", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			label+" did not emit a valid subscription object",
			"inventory subscription rendering",
			"inventory should preserve the visible subscription identity it is summarizing",
		))
	} else {
		for key, expected := range map[string]string{
			"id":           context.Subscription.ID,
			"display_name": context.Subscription.DisplayName,
			"state":        context.Subscription.State,
		} {
			if strings.TrimSpace(expected) == "" {
				continue
			}
			observed, _ := subscription[key].(string)
			if strings.TrimSpace(observed) != strings.TrimSpace(expected) {
				findings = append(findings, makeBlockingFinding(
					fmt.Sprintf("%s-%s-%s-subscription-%s-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint, strings.ReplaceAll(key, "_", "-")),
					fmt.Sprintf("%s reported subscription.%s %q, but Azure context reports %q", label, key, observed, expected),
					"inventory subscription rendering or Azure-backed validation context",
					"inventory should keep subscription identity fields aligned with the Azure account context it is summarizing",
				))
			}
		}
	}

	resourceCountPtr := rowIntPtr(payload, "resource_count")
	resourceCount := 0
	if resourceCountPtr != nil {
		resourceCount = *resourceCountPtr
	}
	if resourceCountPtr == nil || resourceCount != context.ResourceCount {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-resource-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported resource_count %d, but Azure context reports %d", label, resourceCount, context.ResourceCount),
			"inventory resource counting or Azure-backed validation context",
			"inventory should keep visible resource counts aligned with Azure resource enumeration",
		))
	}

	resourceGroupCountPtr := rowIntPtr(payload, "resource_group_count")
	resourceGroupCount := 0
	if resourceGroupCountPtr != nil {
		resourceGroupCount = *resourceGroupCountPtr
	}
	if resourceGroupCountPtr == nil || resourceGroupCount != context.ResourceGroupCount {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-resource-group-count-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported resource_group_count %d, but Azure context reports %d", label, resourceGroupCount, context.ResourceGroupCount),
			"inventory resource-group counting or Azure-backed validation context",
			"inventory should keep visible resource-group counts aligned with Azure resource-group enumeration",
		))
	}

	observedTopTypes := map[string]int{}
	if topTypes, ok := payload["top_resource_types"].(map[string]any); ok {
		for key, value := range topTypes {
			count := 0
			switch typed := value.(type) {
			case float64:
				count = int(typed)
			case int:
				count = typed
			default:
				continue
			}
			observedTopTypes[key] = count
		}
	}
	if !maps.Equal(observedTopTypes, context.TopResourceTypes) {
		findings = append(findings, makeBlockingFinding(
			fmt.Sprintf("%s-%s-%s-top-resource-types-drift", entry.SurfaceKind, entry.SurfaceName, entry.Viewpoint),
			fmt.Sprintf("%s reported top_resource_types %v, but Azure context reports %v", label, observedTopTypes, context.TopResourceTypes),
			"inventory top-resource-type counting or Azure-backed validation context",
			"inventory should keep visible top resource type counts aligned with Azure resource enumeration",
		))
	}

	return findings
}
