package lab

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	entryStartRe     = regexp.MustCompile(`^\s*"([^"]+)":\s*{\s*$`)
	sectionRe        = regexp.MustCompile(`Section:\s*"([^"]+)"`)
	groupedCommandRe = regexp.MustCompile(`GroupedCommand:\s*"([^"]+)"`)
	topLevelFieldsRe = regexp.MustCompile(`(?s)TopLevelFields:\s*\[]string\s*{(.*?)}`)
	quotedValueRe    = regexp.MustCompile(`"([^"]+)"`)
)

type contractBlock struct {
	name string
	text string
}

func extractBlocks(filePath string) ([]contractBlock, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open contract file: %w", err)
	}
	defer file.Close()

	var blocks []contractBlock
	var currentName string
	var currentLines []string
	braceDepth := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if currentName == "" {
			matches := entryStartRe.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			currentName = matches[1]
			currentLines = []string{line}
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		currentLines = append(currentLines, line)
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
		if braceDepth != 0 {
			continue
		}

		blocks = append(blocks, contractBlock{
			name: currentName,
			text: strings.Join(currentLines, "\n"),
		})
		currentName = ""
		currentLines = nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan contract file: %w", err)
	}
	if currentName != "" {
		return nil, fmt.Errorf("unterminated contract block while reading %s", filePath)
	}
	return blocks, nil
}

func extractFlatCommands(filePath string) ([]string, error) {
	blocks, err := extractBlocks(filePath)
	if err != nil {
		return nil, err
	}
	commands := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if !strings.Contains(block.text, "Status:") || !strings.Contains(block.text, "StatusImplemented") {
			continue
		}
		match := sectionRe.FindStringSubmatch(block.text)
		if len(match) > 1 && match[1] == "orchestration" {
			continue
		}
		commands = append(commands, block.name)
	}
	sort.Strings(commands)
	return commands, nil
}

func extractImplementedNames(filePath string) ([]string, error) {
	blocks, err := extractBlocks(filePath)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(blocks))
	for _, block := range blocks {
		if strings.Contains(block.text, "Status:") && strings.Contains(block.text, "StatusImplemented") {
			names = append(names, block.name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func extractFamilyGroupCommands(filePath string) (map[string]string, error) {
	blocks, err := extractBlocks(filePath)
	if err != nil {
		return nil, err
	}
	families := map[string]string{}
	for _, block := range blocks {
		if strings.Contains(block.text, "Status:") && !strings.Contains(block.text, "StatusImplemented") {
			continue
		}
		match := groupedCommandRe.FindStringSubmatch(block.text)
		if len(match) < 2 {
			return nil, fmt.Errorf("family %q is missing GroupedCommand in %s", block.name, filePath)
		}
		families[block.name] = match[1]
	}
	return families, nil
}

func extractCommandTopLevelFields(filePath string) (map[string][]string, error) {
	blocks, err := extractBlocks(filePath)
	if err != nil {
		return nil, err
	}
	commands := map[string][]string{}
	for _, block := range blocks {
		if !strings.Contains(block.text, "Status:") || !strings.Contains(block.text, "StatusImplemented") {
			continue
		}
		match := topLevelFieldsRe.FindStringSubmatch(block.text)
		if len(match) < 2 {
			return nil, fmt.Errorf("command %q is missing TopLevelFields in %s", block.name, filePath)
		}
		fieldMatches := quotedValueRe.FindAllStringSubmatch(match[1], -1)
		fields := make([]string, 0, len(fieldMatches))
		for _, fieldMatch := range fieldMatches {
			fields = append(fields, fieldMatch[1])
		}
		commands[block.name] = fields
	}
	return commands, nil
}

func DeriveSurface(hoAzureDir string) (SurfaceSnapshot, error) {
	resolvedDir, err := filepath.Abs(hoAzureDir)
	if err != nil {
		return SurfaceSnapshot{}, err
	}
	commandsFile := filepath.Join(resolvedDir, "internal", "contracts", "commands.go")
	familiesFile := filepath.Join(resolvedDir, "internal", "contracts", "families.go")

	commands, err := extractFlatCommands(commandsFile)
	if err != nil {
		return SurfaceSnapshot{}, err
	}
	families, err := extractImplementedNames(familiesFile)
	if err != nil {
		return SurfaceSnapshot{}, err
	}
	familyGroupCommands, err := extractFamilyGroupCommands(familiesFile)
	if err != nil {
		return SurfaceSnapshot{}, err
	}
	commandTopLevelFields, err := extractCommandTopLevelFields(commandsFile)
	if err != nil {
		return SurfaceSnapshot{}, err
	}

	return SurfaceSnapshot{
		GeneratedAt:           UTCTimestamp(),
		ToolRepoPath:          resolvedDir,
		Commands:              commands,
		Families:              families,
		FamilyGroupCommands:   familyGroupCommands,
		CommandTopLevelFields: commandTopLevelFields,
	}, nil
}
