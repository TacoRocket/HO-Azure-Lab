package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

func UTCTimestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func LoadJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func WriteJSON(path string, payload any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
