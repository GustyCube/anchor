package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type reasonCodeRegistry struct {
	Version     int      `json:"version"`
	ReasonCodes []string `json:"reason_codes"`
}

type sdkRunnerResult struct {
	Decision       string   `json:"decision"`
	ReasonCodes    []string `json:"reason_codes"`
	ReplayStatus   string   `json:"replay_status"`
	PolicyHashSeen string   `json:"policy_hash_seen"`
}

type parityScenario struct {
	Name            string
	Expected        sdkRunnerResult
	ExpectedReasons []string
}

func TestReasonCodeRegistryParityAcrossSDKSources(t *testing.T) {
	registry := loadReasonCodeRegistry(t)
	root := repoRoot(t)

	observed := map[string][]string{}

	tsContent := readFile(t, filepath.Join(root, "sdk", "typescript", "verifier.ts"))
	tsTypeRe := regexp.MustCompile(`(?s)export type ReasonCode\s*=\s*(.+?);`)
	tsMatch := tsTypeRe.FindStringSubmatch(tsContent)
	if len(tsMatch) != 2 {
		t.Fatal("failed to locate typescript ReasonCode union")
	}
	codeRe := regexp.MustCompile(`"([A-Z0-9_]+)"`)
	for _, m := range codeRe.FindAllStringSubmatch(tsMatch[1], -1) {
		observed["typescript"] = append(observed["typescript"], m[1])
	}

	pyContent := readFile(t, filepath.Join(root, "sdk", "python", "verifier.py"))
	pyListRe := regexp.MustCompile(`(?s)REASON_CODES:\s*List\[str\]\s*=\s*\[(.+?)\]`)
	pyMatch := pyListRe.FindStringSubmatch(pyContent)
	if len(pyMatch) != 2 {
		t.Fatal("failed to locate python REASON_CODES list")
	}
	for _, m := range codeRe.FindAllStringSubmatch(pyMatch[1], -1) {
		observed["python"] = append(observed["python"], m[1])
	}

	javaContent := readFile(t, filepath.Join(root, "sdk", "java", "AnchorLocalVerifier.java"))
	javaClassRe := regexp.MustCompile(`(?s)public static final class ReasonCodes\s*\{(.+?)private ReasonCodes\(\) \{\}`)
	javaMatch := javaClassRe.FindStringSubmatch(javaContent)
	if len(javaMatch) != 2 {
		t.Fatal("failed to locate java ReasonCodes class")
	}
	javaConstRe := regexp.MustCompile(`public static final String [A-Z0-9_]+ = "([A-Z0-9_]+)";`)
	for _, m := range javaConstRe.FindAllStringSubmatch(javaMatch[1], -1) {
		observed["java"] = append(observed["java"], m[1])
	}

	for sdk, codes := range observed {
		if !reflect.DeepEqual(registry.ReasonCodes, codes) {
			t.Fatalf("%s reason codes do not exactly match registry\nexpected=%v\nactual=%v", sdk, registry.ReasonCodes, codes)
		}
	}
}

func TestSDKBehaviorParityAcrossRuntimes(t *testing.T) {
	root := repoRoot(t)
	javaClassDir := buildJavaRunner(t, root)

	runners := []struct {
		Name string
		Run  func(string) (sdkRunnerResult, error)
	}{
		{
			Name: "typescript",
			Run: func(scenario string) (sdkRunnerResult, error) {
				return runSDKCommand(
					root,
					exec.Command(
						"node",
						"--experimental-strip-types",
						filepath.Join(root, "sdk", "typescript", "conformance_runner.ts"),
						scenario,
					),
				)
			},
		},
		{
			Name: "python",
			Run: func(scenario string) (sdkRunnerResult, error) {
				return runSDKCommand(
					root,
					exec.Command(
						"python3",
						filepath.Join(root, "sdk", "python", "conformance_runner.py"),
						scenario,
					),
				)
			},
		},
		{
			Name: "java",
			Run: func(scenario string) (sdkRunnerResult, error) {
				return runSDKCommand(
					root,
					exec.Command(
						"java",
						"-cp",
						javaClassDir,
						"ConformanceRunner",
						scenario,
					),
				)
			},
		},
	}

	scenarios := []parityScenario{
		{
			Name: "authorized",
			Expected: sdkRunnerResult{
				Decision:       "AUTHORIZED",
				ReplayStatus:   "FRESH",
				PolicyHashSeen: "policy-hash-v2",
			},
			ExpectedReasons: []string{},
		},
		{
			Name: "audience_mismatch",
			Expected: sdkRunnerResult{
				Decision:       "REJECTED",
				ReplayStatus:   "FRESH",
				PolicyHashSeen: "policy-hash-v2",
			},
			ExpectedReasons: []string{"ERR_AUDIENCE_MISMATCH", "ERR_AUDIENCE_MISMATCH"},
		},
		{
			Name: "challenge_required",
			Expected: sdkRunnerResult{
				Decision:       "REJECTED",
				ReplayStatus:   "FRESH",
				PolicyHashSeen: "policy-hash-v2",
			},
			ExpectedReasons: []string{"ERR_CHALLENGE_REQUIRED"},
		},
		{
			Name: "policy_hash_mismatch",
			Expected: sdkRunnerResult{
				Decision:       "REJECTED",
				ReplayStatus:   "FRESH",
				PolicyHashSeen: "policy-hash-v2",
			},
			ExpectedReasons: []string{"ERR_POLICY_HASH_MISMATCH"},
		},
		{
			Name: "replay_detected",
			Expected: sdkRunnerResult{
				Decision:       "REJECTED",
				ReplayStatus:   "REPLAY",
				PolicyHashSeen: "policy-hash-v2",
			},
			ExpectedReasons: []string{"ERR_REPLAY_DETECTED"},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			var baseline *sdkRunnerResult
			for _, runner := range runners {
				result, err := runner.Run(scenario.Name)
				if err != nil {
					t.Fatalf("%s runner failed: %v", runner.Name, err)
				}
				if result.Decision != scenario.Expected.Decision {
					t.Fatalf("%s decision mismatch: expected=%s actual=%s", runner.Name, scenario.Expected.Decision, result.Decision)
				}
				if result.ReplayStatus != scenario.Expected.ReplayStatus {
					t.Fatalf("%s replay_status mismatch: expected=%s actual=%s", runner.Name, scenario.Expected.ReplayStatus, result.ReplayStatus)
				}
				if result.PolicyHashSeen != scenario.Expected.PolicyHashSeen {
					t.Fatalf("%s policy_hash_seen mismatch: expected=%s actual=%s", runner.Name, scenario.Expected.PolicyHashSeen, result.PolicyHashSeen)
				}
				if !slices.Equal(result.ReasonCodes, scenario.ExpectedReasons) {
					t.Fatalf("%s reason_codes mismatch: expected=%v actual=%v", runner.Name, scenario.ExpectedReasons, result.ReasonCodes)
				}

				if baseline == nil {
					copyResult := result
					baseline = &copyResult
					continue
				}
				if !reflect.DeepEqual(*baseline, result) {
					t.Fatalf("parity mismatch for %s: baseline=%+v actual=%+v", runner.Name, *baseline, result)
				}
			}
		})
	}
}

func runSDKCommand(root string, cmd *exec.Cmd) (sdkRunnerResult, error) {
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Dir = root
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return sdkRunnerResult{}, fmt.Errorf("run %q: %w (stderr: %s)", strings.Join(cmd.Args, " "), err, strings.TrimSpace(stderr.String()))
	}
	var result sdkRunnerResult
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &result); err != nil {
		return sdkRunnerResult{}, fmt.Errorf("parse sdk output %q: %w", strings.TrimSpace(out.String()), err)
	}
	return result, nil
}

func buildJavaRunner(t *testing.T, root string) string {
	t.Helper()
	outputDir := t.TempDir()
	cmd := exec.Command(
		"javac",
		"-d",
		outputDir,
		filepath.Join(root, "sdk", "java", "AnchorLocalVerifier.java"),
		filepath.Join(root, "sdk", "java", "ConformanceRunner.java"),
	)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("compile java conformance runner: %v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return outputDir
}

func loadReasonCodeRegistry(t *testing.T) reasonCodeRegistry {
	t.Helper()
	registryBytes, err := os.ReadFile("../../spec/reason-codes/reason-codes-v2.json")
	if err != nil {
		t.Fatalf("read reason code registry: %v", err)
	}
	var registry reasonCodeRegistry
	if err := json.Unmarshal(registryBytes, &registry); err != nil {
		t.Fatalf("parse reason code registry: %v", err)
	}
	if registry.Version != 2 {
		t.Fatalf("expected reason code registry version 2, got %d", registry.Version)
	}
	if len(registry.ReasonCodes) == 0 {
		t.Fatal("expected non-empty reason code registry")
	}
	return registry
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
