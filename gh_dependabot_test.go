package main

import (
	"testing"

	"github.com/cli/go-gh"
	"github.com/cli/go-gh/pkg/api"
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
}

func TestContentToVersion(t *testing.T) {
	if contentToVersion("", "testpkg") != "" {
		t.Error("`testpkg` is not in empty string")
	}

	if contentToVersion("apkg@1.2.3\ntestpkg@4.5.6\nsomepkg@7.8.9", "testpkg") != "4.5.6" {
		t.Error("Unable to find `testpkg`")
	}

	if contentToVersion("TestPkg@1.2.3", "testpkg") != "1.2.3" {
		t.Error("Case insensitive search failed for `testpkg`")
	}

	if contentToVersion("testpkg@1.2alpha", "testpkg") != "1.2alpha" {
		t.Error("Version string should be `1.2alpha`")
	}

	if contentToVersion("testpkg@1.2.3:deadbeef", "testpkg") != "1.2.3" {
		t.Error("Version string should be `1.2.3`")
	}
}

func mockGetContents(client api.RESTClient, repoOwner string, repoName string, manifestPath string) string {
	return "apkg@1.2.3\ntestpkg@4.5.6\nsomepkg@7.8.9"
}

func TestProcessFindings(t *testing.T) {
	client, _ := gh.RESTClient(nil)

	dependabotResponses := []DependabotResponse{}

	dependabotResponses = append(dependabotResponses, DependabotResponse{
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

	dependabotResponses = append(dependabotResponses, DependabotResponse{
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

	findings := make(map[string]Finding)
	processFindings(client, "octocat", "example-repo", dependabotResponses, mockGetContents, findings)

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
