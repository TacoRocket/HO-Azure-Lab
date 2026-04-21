package lab

import (
	"fmt"
	"io"
)

func captureLiveCredentialPathContext(outdir, workingDir string, env []string, progressWriter io.Writer) error {
	captures := []struct {
		name string
		fn   func(string, string, []string, io.Writer) error
	}{
		{name: "tokens-credentials", fn: captureLiveTokensCredentialsContext},
		{name: "databases", fn: captureLiveDatabasesContext},
		{name: "keyvault", fn: captureLiveKeyVaultContext},
		{name: "storage", fn: captureLiveStorageContext},
	}
	for _, capture := range captures {
		if err := capture.fn(outdir, workingDir, env, progressWriter); err != nil {
			return fmt.Errorf("capture %s context for credential-path: %w", capture.name, err)
		}
	}
	return nil
}
