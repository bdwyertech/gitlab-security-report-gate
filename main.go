package main

import (
	"encoding/json"
	"os"

	log "github.com/sirupsen/logrus"

	"gitlab.com/gitlab-org/security-products/analyzers/report/v2"
)

func main() {
	reportFile, err := os.ReadFile("gl-secret-detection-report.json")
	if err != nil {
		log.Fatal(err)
	}

	var r report.Report
	err = json.Unmarshal(reportFile, &r)
	if err != nil {
		log.Fatal(err)
	}

	var result []string

	if len(r.Vulnerabilities) > 0 {
		for _, v := range r.Vulnerabilities {
			out, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				log.Fatal(err)
			}
			result = append(result, string(out))
		}
	}

	if len(result) > 0 {
		log.Fatalf("%d Vulnerabilities detected:\n%s\n", len(result), result)
	}
}
