package lab

import (
	"errors"
	"reflect"
	"testing"
)

func TestEventGridEnumerationScopesFromAzureIncludesGlobalAndRegionalScopes(t *testing.T) {
	topicTypes := []map[string]any{
		{
			"name": "Microsoft.Storage.StorageAccounts",
			"properties": map[string]any{
				"supportedScopesForSource": []any{"AzureSubscription", "Resource"},
				"supportedLocations":       []any{"centralus", "eastus"},
			},
		},
		{
			"name": "Microsoft.Resources.Subscriptions",
			"properties": map[string]any{
				"resourceRegionType": "GlobalResource",
			},
		},
	}

	got := eventGridEnumerationScopesFromAzure("sub-123", topicTypes, []string{"centralus", "westus"})
	want := []eventGridEnumerationScope{
		{
			path:       "/subscriptions/sub-123/providers/Microsoft.EventGrid/topicTypes/Microsoft.Storage.StorageAccounts/eventSubscriptions",
			issueScope: "event-grid.topic-type[Microsoft.Storage.StorageAccounts]",
		},
		{
			path:       "/subscriptions/sub-123/providers/Microsoft.EventGrid/locations/centralus/topicTypes/Microsoft.Storage.StorageAccounts/eventSubscriptions",
			issueScope: "event-grid.topic-type[Microsoft.Storage.StorageAccounts@centralus]",
		},
		{
			path:       "/subscriptions/sub-123/providers/Microsoft.EventGrid/topicTypes/Microsoft.Resources.Subscriptions/eventSubscriptions",
			issueScope: "event-grid.topic-type[Microsoft.Resources.Subscriptions]",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected enumeration scopes: got %#v want %#v", got, want)
	}
}

func TestEventGridEnumerationScopesFromAzureNormalizesAzureLocationSpellings(t *testing.T) {
	topicTypes := []map[string]any{
		{
			"name": "Microsoft.Storage.StorageAccounts",
			"properties": map[string]any{
				"resourceRegionType": "RegionalResource",
				"supportedLocations": []any{"Central US"},
			},
		},
	}

	got := eventGridEnumerationScopesFromAzure("sub-123", topicTypes, []string{"centralus"})
	want := []eventGridEnumerationScope{
		{
			path:       "/subscriptions/sub-123/providers/Microsoft.EventGrid/locations/centralus/topicTypes/Microsoft.Storage.StorageAccounts/eventSubscriptions",
			issueScope: "event-grid.topic-type[Microsoft.Storage.StorageAccounts@centralus]",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected normalized scopes: got %#v want %#v", got, want)
	}
}

func TestEventGridItemsFromEnumerationScopesIgnoresExpectedErrorsAndDedupes(t *testing.T) {
	scopes := []eventGridEnumerationScope{
		{path: "/scope-a", issueScope: "scope-a"},
		{path: "/scope-b", issueScope: "scope-b"},
		{path: "/scope-c", issueScope: "scope-c"},
	}

	items, err := eventGridItemsFromEnumerationScopes(scopes, func(scope eventGridEnumerationScope) ([]map[string]any, error) {
		switch scope.path {
		case "/scope-a":
			return []map[string]any{{"id": "/route/1"}}, nil
		case "/scope-b":
			return nil, errors.New("ResourceNotFound: 404")
		case "/scope-c":
			return []map[string]any{{"id": "/route/1"}, {"id": "/route/2"}}, nil
		default:
			return nil, errors.New("unexpected scope")
		}
	})
	if err != nil {
		t.Fatalf("eventGridItemsFromEnumerationScopes returned error: %v", err)
	}

	got := []string{
		stringValue(items[0]["id"]),
		stringValue(items[1]["id"]),
	}
	want := []string{"/route/1", "/route/2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected route IDs: got %#v want %#v", got, want)
	}
}

func TestEventGridItemsFromEnumerationScopesFailsOnUnexpectedError(t *testing.T) {
	scopes := []eventGridEnumerationScope{
		{path: "/scope-a", issueScope: "scope-a"},
	}

	_, err := eventGridItemsFromEnumerationScopes(scopes, func(scope eventGridEnumerationScope) ([]map[string]any, error) {
		return nil, errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected unexpected enumeration error to be returned")
	}
}
