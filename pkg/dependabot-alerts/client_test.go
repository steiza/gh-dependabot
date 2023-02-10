package da

import (
	"testing"

	dg "github.com/steiza/gh-dependabot/pkg/dependency-graph"
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
	alertResponses := []AlertResponse{}

	alertResponses = append(alertResponses, AlertResponse{
		Number: 1,
		State:  "open",
		Dependency: Dependency{
			ManifestPath: "a/s/d/f",
		},
		SecurityAdvisory: SecurityAdvisory{
			Summary: "Something happened",
		},
		SecurityVulnerability: SecurityVulnerability{
			Package: Package{
				Ecosystem: "pip",
				Name:      "TestPkg",
			},
			Severity: "critical",
			FirstPatchedVersion: FirstPatchedVersion{
				Identifier: "5.0.0",
			},
		},
	})

	alertResponses = append(alertResponses, AlertResponse{
		Number: 2,
		State:  "open",
		Dependency: Dependency{
			ManifestPath: "a/s/d/f",
		},
		SecurityAdvisory: SecurityAdvisory{
			Summary: "Something else happened",
		},
		SecurityVulnerability: SecurityVulnerability{
			Package: Package{
				Ecosystem: "pip",
				Name:      "TestPkg",
			},
			Severity: "high",
			FirstPatchedVersion: FirstPatchedVersion{
				Identifier: "5.0.1",
			},
		},
	})

	dependencyMap := dg.DependencyMap{
		"a/s/d/f": {
			"pip": {
				"testpkg": "> 1.2.3",
			},
		},
	}

	findings := make(map[string]Finding)

	processFindings(alertResponses, dependencyMap, findings)

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
