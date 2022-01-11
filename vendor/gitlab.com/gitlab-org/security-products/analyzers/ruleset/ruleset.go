// Package ruleset provides code for the analyzer to use to load external scanner configurations.
// These rulesets are loaded from .gitlab/{sast}-ruleset.toml.
package ruleset

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/pelletier/go-toml"
)

const (
	// EnvVarGitlabFeatures lists Gitlab features available
	EnvVarGitlabFeatures = "GITLAB_FEATURES"
	// GitlabFeatureCustomRulesetsSAST indicates that sast custom rulesets are enabled
	GitlabFeatureCustomRulesetsSAST = "sast_custom_rulesets"
	// PathSAST is the default path to custom sast rules
	PathSAST = ".gitlab/sast-ruleset.toml"
	// PathSecretDetection is the default path to custom secret detection rulesets
	PathSecretDetection = ".gitlab/secret-detection-ruleset.toml" // #nosec
	// PassThroughFile should be used when the ruleset passthrough is a file.
	PassThroughFile PassThroughType = "file"
	// PassThroughRaw should be used when the ruleset passthrough is defined inline.
	PassThroughRaw PassThroughType = "raw"
)

// PassThroughType determines how the analyzer loads the ruleset which can either be via a
// file or defined inline.
type PassThroughType string

// Config is used for overriding default scanner configurations for the analyzers.
type Config struct {
	PassThrough []PassThrough
	Ruleset     []Ruleset
	Path        string
}

// PassThrough is a struct that analyzers use to load external scanner configurations. Users can define
// in a project's ruleset file a PassThroughType (file, raw) and a value. Depending on the type, the value will
// either be a scanner specific file configuration or an inline configuration.
type PassThrough struct {
	Type   PassThroughType
	Target string
	Value  string
}

// Identifier is a vulnerability id. Identifier.Value is used to
// filter or override vulnerability information in the final report.
type Identifier struct {
	Type  string
	Value string
}

// Ruleset is used for disabling rules
type Ruleset struct {
	Identifier Identifier
	Disable    bool
}

// Load accepts a rulesetPath and analyzer. Rulesetpath must point to a valid {sast}-ruleset.toml file.
// A single analyzer rule will be returned if one is found.
func Load(rulesetPath string, analyzer string) (*Config, error) {
	if !customRulesetEnabled() {
		return nil, &NotEnabledError{}
	}

	if _, err := os.Stat(rulesetPath); err != nil && os.IsNotExist(err) {
		return nil, &ConfigFileNotFoundError{
			RulesetPath: rulesetPath,
		}
	}

	b, err := ioutil.ReadFile(rulesetPath) // #nosec
	if err != nil {
		return nil, err
	}

	configs := make(map[string]Config)
	if err = toml.Unmarshal(b, &configs); err != nil {
		return nil, &InvalidConfig{
			RulesetPath: rulesetPath,
			Err:         err,
		}
	}

	if config, ok := configs[analyzer]; ok {
		return &config, nil
	}

	return nil, &ConfigNotFoundError{
		Analyzer:    analyzer,
		RulesetPath: rulesetPath,
	}
}

// DisabledIdentifiers uses the config pre-loaded by the analyzer then
// constructs a list of identifiers that will be ignored when reporting vulnerabilities
func DisabledIdentifiers(rulesetPath string, analyzer string) (map[string]bool, error) {
	config, err := Load(rulesetPath, analyzer)
	if err != nil {
		return map[string]bool{}, err
	}

	disabledIdentifiers := make(map[string]bool)
	for _, ruleset := range config.Ruleset {
		if ruleset.Disable {
			disabledIdentifiers[ruleset.Identifier.Value] = true
		}
	}

	return disabledIdentifiers, nil
}

// customRulesetEnabled checks if custom rulesets are enabled.
func customRulesetEnabled() bool {
	if features := os.Getenv(EnvVarGitlabFeatures); !strings.Contains(features, GitlabFeatureCustomRulesetsSAST) {
		return false
	}
	return true
}
