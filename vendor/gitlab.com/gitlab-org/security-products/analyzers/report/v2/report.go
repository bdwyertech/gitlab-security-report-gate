package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
)

const timeFormat = "2006-01-02T15:04:05"

// ScanTime is a custom time type formatted using the timeFormat
type ScanTime time.Time

// Status represents the status of a scan, either `success` or `failure`
type Status string

const (
	// StatusSuccess is the identifier for a successful scan
	StatusSuccess Status = "success"
	// StatusFailure is the identifier for a failed scan
	StatusFailure Status = "failure"
)

// Vendor is the vendor/maintainer of the scanner
type Vendor struct {
	Name string `json:"name"` // The name of the vendor
}

// ScannerDetails contains detailed information about the scanner
type ScannerDetails struct {
	ID      string `json:"id"`            // Unique id that identifies the scanner
	Name    string `json:"name"`          // A human readable value that identifies the scanner, not required to be unique
	URL     string `json:"url,omitempty"` // A link to more information about the scanner
	Vendor  Vendor `json:"vendor"`        // The vendor/maintainer of the scanner
	Version string `json:"version"`       // The version of the scanner
}

// Scan contains the identifying information about a security scanner.
type Scan struct {
	Scanner   ScannerDetails `json:"scanner"`              // Scanner is an Object defining the scanner used to perform the scan
	Type      Category       `json:"type"`                 // Type of the scan (container_scanning, dependency_scanning, dast, sast)
	StartTime *ScanTime      `json:"start_time,omitempty"` // StartTime is the time when the scan started
	EndTime   *ScanTime      `json:"end_time,omitempty"`   // EndTime is the time when the scan ended
	Status    Status         `json:"status,omitempty"`     // Status is the status of the scan, either `success` or `failure`. Hardcoded to `success` for now
}

// Report is the output of an analyzer.
type Report struct {
	Version         Version          `json:"version"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
	Remediations    []Remediation    `json:"remediations"`
	DependencyFiles []DependencyFile `json:"dependency_files,omitempty"`
	Scan            Scan             `json:"scan"`
	Analyzer        string           `json:"-"`
	Config          ruleset.Config   `json:"-"`
}

// MarshalJSON converts the ScanTime value into a JSON string with the defined timeFormat
func (st *ScanTime) MarshalJSON() ([]byte, error) {
	return []byte(st.String()), nil
}

// UnmarshalJSON converts the JSON string with the defined timeFormat into a ScanTime value
func (st *ScanTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)

	parsedTime, err := time.Parse(timeFormat, s)
	*st = ScanTime(parsedTime)

	return err
}

func (st *ScanTime) String() string {
	t := time.Time(*st)
	return fmt.Sprintf("%q", t.Format(timeFormat))
}

func (s ScannerDetails) String() string {
	return fmt.Sprintf("%s %s analyzer v%s", s.Vendor.Name, s.Name, s.Version)
}

// Sort sorts vulnerabilities by decreasing severity.
func (r *Report) Sort() {
	// sort vulnerabilities by severity, compare key
	sort.Slice(r.Vulnerabilities, func(i, j int) bool {
		si, sj := r.Vulnerabilities[i].Severity, r.Vulnerabilities[j].Severity
		if si == sj {
			return r.Vulnerabilities[i].CompareKey < r.Vulnerabilities[j].CompareKey
		}
		return si > sj
	})

	// sort dependency files by path
	sort.Slice(r.DependencyFiles, func(i, j int) bool {
		return r.DependencyFiles[i].Path < r.DependencyFiles[j].Path
	})

	// sort remediations by the CompareKey
	sort.Slice(r.Remediations, func(i, j int) bool {
		return r.Remediations[i].Fixes[0].CompareKey < r.Remediations[j].Fixes[0].CompareKey
	})

	// sort dependencies by name, version
	for _, df := range r.DependencyFiles {
		sort.Slice(df.Dependencies, func(i, j int) bool {
			ni, nj := df.Dependencies[i].Package.Name, df.Dependencies[j].Package.Name
			if ni == nj {
				return df.Dependencies[i].Version < df.Dependencies[j].Version
			}
			return ni < nj
		})
	}
}

// ExcludePaths excludes paths from vulnerabilities, remediations, and dependency files.
// It takes a function that is true when the given path is excluded.
func (r *Report) ExcludePaths(isExcluded func(string) bool) {
	// filter vulnerabilities
	vulns := []Vulnerability{}
	var rejCompareKeys []string
	for _, vuln := range r.Vulnerabilities {
		if isExcluded(vuln.Location.File) {
			rejCompareKeys = append(rejCompareKeys, vuln.CompareKey)
		} else {
			vulns = append(vulns, vuln)
		}
	}

	if len(rejCompareKeys) > 0 {
		sliceCap := len(rejCompareKeys)
		if len(rejCompareKeys) > 10 {
			sliceCap = 10
		}
		log.Debugf("Excluded %v findings matching path exclusions. First 10: %v", len(rejCompareKeys), rejCompareKeys[:sliceCap])
	}

	r.Vulnerabilities = vulns

	// filter remediations
	rems := []Remediation{}
remloop:
	for _, rem := range r.Remediations {
		for _, ref := range rem.Fixes {
			for _, ckey := range rejCompareKeys {
				if ckey == ref.CompareKey {
					continue remloop
				}
			}
		}
		rems = append(rems, rem)
	}
	r.Remediations = rems

	// filter dependencies
	depfiles := []DependencyFile{}
	for _, depfile := range r.DependencyFiles {
		if !isExcluded(depfile.Path) {
			depfiles = append(depfiles, depfile)
		}
	}
	r.DependencyFiles = depfiles
}

// Dedupe removes duplicates from vulnerabilities
func (r *Report) Dedupe() {
	r.Vulnerabilities = Dedupe(r.Vulnerabilities...)
}

// NewReport creates a new report in current version.
func NewReport() Report {
	return Report{
		Version:         CurrentVersion(),
		Vulnerabilities: []Vulnerability{},
		Remediations:    []Remediation{},
		DependencyFiles: []DependencyFile{},
		Scan:            Scan{},
	}
}

// MergeReports merges the given reports and bring them to the current syntax version.
func MergeReports(reports ...Report) Report {
	report := NewReport()
	for _, r := range reports {
		report.Vulnerabilities = append(report.Vulnerabilities, r.Vulnerabilities...)
		report.Remediations = append(report.Remediations, r.Remediations...)
		report.DependencyFiles = append(report.DependencyFiles, r.DependencyFiles...)
	}
	report.Dedupe()
	report.Sort()
	return report
}

// FilterDisabledRules removes vulnerabilities that have been disabled using rulesets
func (r *Report) FilterDisabledRules(rulesetPath string, analyzer string) {
	if rulesetPath == "" {
		return
	}
	disabledIds, err := ruleset.DisabledIdentifiers(rulesetPath, analyzer)
	if err != nil {
		switch err.(type) {
		case *ruleset.NotEnabledError:
			log.Debug(err)
		case *ruleset.ConfigFileNotFoundError:
			log.Debug(err)
		case *ruleset.ConfigNotFoundError:
			log.Debug(err)
		case *ruleset.InvalidConfig:
			log.Fatal(err)
		default:
			log.Error(err)
		}
		return
	}
	if len(disabledIds) == 0 {
		return
	}

	vulns := []Vulnerability{}
	for _, vuln := range r.Vulnerabilities {
		if vulnerabilityEnabled(vuln, disabledIds) {
			vulns = append(vulns, vuln)
		}
	}
	r.Vulnerabilities = vulns
	return
}

func vulnerabilityEnabled(vuln Vulnerability, disabledIds map[string]bool) bool {
	for _, id := range vuln.Identifiers {
		if _, ok := disabledIds[id.Value]; ok {
			return false
		}
	}
	return true
}
