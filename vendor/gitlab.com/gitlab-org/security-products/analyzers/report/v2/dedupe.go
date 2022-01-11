package report

import (
	//  Used for location fingerprinting, not cryptographically secure
	"crypto/sha1" // #nosec
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// Dedupe removes duplicates from a given list of vulnerabilities.
// Duplicates shares the same location and at least one identifier.
// CWE ids are ignored since these are used to classify the vulnerability.
// First duplicate in the list wins and others are simply removed.
func Dedupe(vulnerabilities ...Vulnerability) []Vulnerability {
	type keyType struct {
		locSHA1 string         // SHA1 of string representation of location
		idType  IdentifierType // identifier type
		idValue string         // identifier value
	}

	var seen = make(map[keyType]bool)  // keys that have been seen already
	var out = make([]Vulnerability, 0) // vulnerabilities that are returned

	for _, vulnerability := range vulnerabilities {
		// turn location into a SHA1
		h := sha1.New() // #nosec
		b, err := json.Marshal(vulnerability.Location)
		if err != nil {
			log.Error("could not create location hash", err)
			continue
		}
		if _, err := h.Write(b); err != nil {
			log.Error("could not hash vulnerability location", err)
			continue
		}
		locSHA1 := fmt.Sprintf("%x", h.Sum(nil))

		// iterate over identifiers
		var alreadySeen bool
	innerLoop:
		for _, id := range vulnerability.Identifiers {
			switch id.Type {
			case IdentifierTypeCWE:
				// ignored
			default:
				var key = keyType{locSHA1, id.Type, id.Value}
				if _, found := seen[key]; found {
					alreadySeen = true
					break innerLoop
				}
				seen[key] = true
			}
		}
		if !alreadySeen {
			out = append(out, vulnerability)
		}
	}

	return out
}
