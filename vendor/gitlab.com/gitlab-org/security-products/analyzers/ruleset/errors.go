package ruleset

import (
	"fmt"
)

// NotEnabledError indicates custom rulesets have not been enabled
type NotEnabledError struct{}

// Error formats and returns a NotEnabledError
func (e *NotEnabledError) Error() string { return "custom rulesets not enabled" }

// ConfigFileNotFoundError indicates the config file was not found
type ConfigFileNotFoundError struct {
	RulesetPath string
}

// Error formats and returns a ConfigFileNotFoundError
func (e *ConfigFileNotFoundError) Error() string {
	return fmt.Sprintf("%s not found, ruleset support will be disabled.", e.RulesetPath)
}

// ConfigNotFoundError indicates custom rule config is not found
type ConfigNotFoundError struct {
	Analyzer    string
	RulesetPath string
}

// Error formats and returns a ConfigNotFoundError
func (e *ConfigNotFoundError) Error() string {
	return fmt.Sprintf("analyzer: %[1]v, the ruleset at path `%[2]v` did not contain a configuration directive for the `%[1]v` analyzer, ruleset support will be disabled.", e.Analyzer, e.RulesetPath)
}

// InvalidConfig indicates an invalid toml file
type InvalidConfig struct {
	RulesetPath string
	Err         error
}

// Error formats and returns an InvalidConfig
func (e *InvalidConfig) Error() string {
	return fmt.Sprintf("%s is invalid. Received the following errors when unmarshaling toml: %s", e.RulesetPath, e.Err)
}
