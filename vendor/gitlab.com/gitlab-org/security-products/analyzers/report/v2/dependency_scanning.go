package report

import "strings"

// DependencyScanningVulnerability can calculate some vulnerability fields automatically.
type DependencyScanningVulnerability struct {
	Vulnerability
}

// ToVulnerability returns an vulnerability where some fields are set automatically:
// - CompareKey
// - Message when undefined
func (v DependencyScanningVulnerability) ToVulnerability() Vulnerability {
	i := v.Vulnerability
	i.CompareKey = v.compareKey()
	if len(i.Message) == 0 {
		i.Message = v.defaultMessage()
	}
	return i
}

// defaultMessage generates the Message using the Name, else the Location.
func (v DependencyScanningVulnerability) defaultMessage() string {
	name := v.Vulnerability.Name
	pkg := v.Vulnerability.Location.Dependency.Package.Name
	if len(name) > 0 {
		return name + " in " + pkg
	}
	return "Vulnerability in " + pkg
}

// compareKey generates the CompareKey using the location and the primary identifier.
func (v DependencyScanningVulnerability) compareKey() string {
	file := v.Location.File
	pkg := v.Location.Dependency.Package.Name
	parts := []string{file, pkg}
	if len(v.Identifiers) > 0 {
		t, v := v.Identifiers[0].Type, v.Identifiers[0].Value
		parts = append(parts, string(t), v)
	}
	return strings.Join(parts, ":")
}
