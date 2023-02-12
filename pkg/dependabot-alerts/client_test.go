package da

import (
	"testing"
)

func TestSemverLess(t *testing.T) {
	if !semverLess("1.2.3", "4.5.6") {
		t.Error("1.2.3 should be less than 4.5.6")
	}

	if semverLess("4.5.6", "1.2.3") {
		t.Error("4.5.6 should not be less than 1.2.3")
	}

	if !semverLess("12.13.14", "12.13.15") {
		t.Error("12.13.14 should be less than 12.13.15")
	}

	if semverLess("12.13.15", "12.13.14") {
		t.Error("12.13.15 should not be less than 12.13.14")
	}

	if !semverLess("= 1.2.3", "> 4.5.6") {
		t.Error("1.2.3 should be less than 4.5.6")
	}
}

func TestProcessFindings(t *testing.T) {
	var nodes []Node

	nodes = append(nodes, Node{
		Number: 1,
		SecurityAdvisory: SecurityAdvisory{
			Summary: "Something happened",
		},
		SecurityVulnerability: SecurityVulnerability{
			Package: Package{
				Ecosystem: "pip",
				Name:      "TestPkg",
			},
			Severity: "CRITICAL",
			FirstPatchedVersion: FirstPatchedVersion{
				Identifier: "5.0.0",
			},
		},
		State:                  "open",
		VulnerableManifestPath: "a/s/d/f",
		VulnerableRequirements: "1.2.3",
	})

	nodes = append(nodes, Node{
		Number: 2,
		SecurityAdvisory: SecurityAdvisory{
			Summary: "Something else happened",
		},
		SecurityVulnerability: SecurityVulnerability{
			Package: Package{
				Ecosystem: "pip",
				Name:      "TestPkg",
			},
			Severity: "HIGH",
			FirstPatchedVersion: FirstPatchedVersion{
				Identifier: "5.0.1",
			},
		},
		State:                  "open",
		VulnerableManifestPath: "a/s/d/f",
	})

	query := Query{
		Repository{
			VulnerabilityAlerts{
				Nodes: nodes,
			},
		},
	}

	findings := make(map[string]Finding)

	processFindings(&query, findings)

	finding, ok := findings["testpkg (pip)"]

	if !ok {
		t.Error("`processFindings` unable to find `testpkg`")
	}

	if finding.Count != 2 {
		t.Error("`processFindings` should have `Count` of `2`")
	}

	if finding.TopSummarySeverity != 4 {
		t.Error("`processFindings` should have `TopSummarySeverity` of `4`")
	}

	if finding.TopPatchedVersion != "5.0.1" {
		t.Error("`processFindings` should have `TopPatchedVersion` of `5.0.1`")
	}
}
