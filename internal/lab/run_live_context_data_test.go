package lab

import "testing"

func TestStorageValidationDefaultActionPrefersNetworkRuleSetThenNetworkACLs(t *testing.T) {
	testCases := []struct {
		name       string
		properties azStorageAccountProperties
		want       string
	}{
		{
			name: "network rule set",
			properties: azStorageAccountProperties{
				NetworkRuleSet: azStorageNetworkRuleSet{DefaultAction: "Allow"},
			},
			want: "Allow",
		},
		{
			name: "network acls fallback",
			properties: azStorageAccountProperties{
				NetworkACLs: azStorageNetworkRuleSet{DefaultAction: "Deny"},
			},
			want: "Deny",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := storageValidationDefaultAction(testCase.properties); got != testCase.want {
				t.Fatalf("storageValidationDefaultAction() = %q, want %q", got, testCase.want)
			}
		})
	}
}
