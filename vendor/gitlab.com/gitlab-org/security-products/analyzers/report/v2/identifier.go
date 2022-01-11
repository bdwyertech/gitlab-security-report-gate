package report

import (
	"fmt"
	"strconv"
	"strings"
)

// IdentifierType is the unique ID ("slug") for identifier "kind" bound to a certain vulnerabilities database (CVE, CWE, etc.)
type IdentifierType string

const (
	// IdentifierTypeCVE is the identifier type for CVE IDs (https://cve.mitre.org/cve/)
	IdentifierTypeCVE IdentifierType = "cve"
	// IdentifierTypeCWE is the identifier type for CWE IDs (https://cwe.mitre.org/data/index.html)
	IdentifierTypeCWE IdentifierType = "cwe"
	// IdentifierTypeOSVDB is the identifier type for OSVDB IDs (https://cve.mitre.org/data/refs/refmap/source-OSVDB.html)
	IdentifierTypeOSVDB IdentifierType = "osvdb"
	// IdentifierTypeUSN is the identifier type for Ubuntu Security Notice IDs (https://usn.ubuntu.com/)
	IdentifierTypeUSN IdentifierType = "usn"
	// IdentifierTypeWASC is the identifier type for WASC IDs (http://projects.webappsec.org/Threat-Classification-Reference-Grid)
	IdentifierTypeWASC IdentifierType = "wasc"

	// IdentifierTypeRHSA is the identifier type for RHSA IDs (https://access.redhat.com/errata)
	IdentifierTypeRHSA IdentifierType = "rhsa"

	// IdentifierTypeELSA is the identifier type for Oracle Linux Security Data IDs (https://linux.oracle.com/security/)
	IdentifierTypeELSA IdentifierType = "elsa"

	// IdentifierTypeH1 is the identifier type for IDs in hackerone reports (https://api.hackerone.com/core-resources/#reports)
	IdentifierTypeH1 IdentifierType = "hackerone"
)

var (
	wascThreatSlugs = []string{ // index+1 is the corresponding integer WASC ID
		"Insufficient-Authentication",
		"Insufficient-Authorization",
		"Integer-Overflows",
		"Insufficient-Transport-Layer-Protection",
		"Remote-File-Inclusion",
		"Format-String",
		"Buffer-Overflow",
		"Cross-Site-Scripting",
		"Cross-Site-Request-Forgery",
		"Denial-of-Service",
		"Brute-Force",
		"Content-Spoofing",
		"Information-Leakage",
		"Server-Misconfiguration",
		"Application-Misconfiguration",
		"Directory-Indexing",
		"Improper-Filesystem Permissions",
		"Credential-And-Session-Prediction",
		"SQL-Injection",
		"Improper-Input-Handling",
		"Insufficient+Anti-Automation",
		"Improper-Output-Handling",
		"XML-Injection",
		"HTTP-Request-Splitting",
		"HTTP-Response-Splitting",
		"HTTP-Request-Smuggling",
		"HTTP-Response-Smuggling",
		"Null-Byte-Injection",
		"LDAP-Injection",
		"Mail-Command-Injection",
		"OS-Commanding",
		"Routing-Detour",
		"Path-Traversal",
		"Predictable-Resource-Location",
		"SOAP-Array-Abuse",
		"SSI-Injection",
		"Session-Fixation",
		"URL-Redirector-Abuse",
		"XPath-Injection",
		"Insufficient-Process-Validation",
		"XML-Attribute-Blowup",
		"Abuse-of-Functionality",
		"XML-External-Entities",
		"XML-Entity-Expansion",
		"Fingerprinting",
		"XQuery-Injection",
		"Insufficient-Session-Expiration",
		"Insecure-Indexing",
		"Insufficient-Password-Recovery",
		"Insufficient-Data-Protection",
	}
)

// Identifier holds reference and matching information about a concrete vulnerability
type Identifier struct {
	Type  IdentifierType `json:"type"`          // Type of the identifier (CVE, CWE, VENDOR_X, etc.)
	Name  string         `json:"name"`          // Name of the identifier for display purpose
	Value string         `json:"value"`         // Value of the identifier for matching purpose
	URL   string         `json:"url,omitempty"` // URL to identifier's documentation
}

// ParseIdentifierID builds an Identifier of correct IdentifierType from a human-readable ID slug
// (e.g., "CWE-1", "WASC-01")
func ParseIdentifierID(idStr string) (Identifier, bool) {
	parts := strings.SplitN(idStr, "-", 2)
	switch strings.ToUpper(parts[0]) {
	case "CVE":
		return CVEIdentifier(idStr), true
	case "CWE":
		if idInt, err := strconv.Atoi(parts[1]); err == nil {
			return CWEIdentifier(idInt), true
		}
	case "OSVDB":
		return OSVDBIdentifier(idStr), true
	case "USN":
		return USNIdentifier(idStr), true
	case "WASC":
		if idInt, err := strconv.Atoi(parts[1]); err == nil {
			return WASCIdentifier(idInt), true
		}
	case "RHSA":
		return RHSAIdentifier(idStr), true
	case "ELSA":
		return ELSAIdentifier(idStr), true
	case "HACKERONE":
		return H1Identifier(idStr), true
	}
	return Identifier{}, false
}

// CVEIdentifier returns a structured Identifier for a given CVE-ID
// Given ID must follow this format: CVE-YYYY-NNNNN
func CVEIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeCVE,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", ID),
	}
}

// CWEIdentifier returns a structured Identifier for a given CWE ID
// Given ID must follow this format: NNN (just the number, no prefix)
func CWEIdentifier(ID int) Identifier {
	return Identifier{
		Type:  IdentifierTypeCWE,
		Name:  fmt.Sprintf("CWE-%d", ID),
		Value: strconv.Itoa(ID),
		URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", ID),
	}
}

// OSVDBIdentifier returns a structured Identifier for a given OSVDB-ID
// Given ID must follow this format: OSVDB-XXXXXX
func OSVDBIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeOSVDB,
		Name:  ID,
		Value: ID,
		URL:   "https://cve.mitre.org/data/refs/refmap/source-OSVDB.html",
	}
}

// USNIdentifier returns a structured Identifier for a Ubuntu Security Notice.
// Given ID must follow this format: USN-XXXXXX.
func USNIdentifier(ID string) Identifier {
	parts := strings.SplitN(ID, "-", 2)
	return Identifier{
		Type:  IdentifierTypeUSN,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://usn.ubuntu.com/%s/", parts[1]),
	}
}

// WASCIdentifier returns a structured Identifier for a given WASC-ID
// (Web Application Security Consortium vulnerability ID)
// Given ID must follow this format: NN (just the number, no prefix)
func WASCIdentifier(ID int) Identifier {
	return Identifier{
		Type:  IdentifierTypeWASC,
		Name:  fmt.Sprintf("WASC-%02d", ID),
		Value: fmt.Sprintf("%d", ID),
		URL:   wascURL(ID),
	}
}

// RHSAIdentifier returns a structured Identifier for a given RHSA-ID
// Given ID must follow this format: RHSA-YYYY:NNNN
func RHSAIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeRHSA,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://access.redhat.com/errata/%s", ID),
	}
}

// ELSAIdentifier returns a structured Identifier for a given ELSA-ID
// Given ID must follow this format: ELSA-YYYY-NNNN(-N)?$
func ELSAIdentifier(ID string) Identifier {
	return Identifier{
		Type:  IdentifierTypeELSA,
		Name:  ID,
		Value: ID,
		URL:   fmt.Sprintf("https://linux.oracle.com/errata/%s.html", ID),
	}
}

// H1Identifier returns a structured Identifier for a given hackerone report
// Given ID must follow this format: HACKERONE-XXXXXX
// The HACKERONE prefix is an internal GitLab identifier and is ignored in
// the value field
func H1Identifier(ID string) Identifier {
	parts := strings.SplitN(ID, "-", 2)
	return Identifier{
		Type:  IdentifierTypeH1,
		Name:  ID,
		Value: parts[1],
		URL:   fmt.Sprintf("https://hackerone.com/reports/%s", parts[1]),
	}
}

func wascURL(ID int) string {
	if ID >= 1 && ID <= len(wascThreatSlugs) {
		return fmt.Sprintf("http://projects.webappsec.org/%s", wascThreatSlugs[ID-1])
	}
	return ""
}
