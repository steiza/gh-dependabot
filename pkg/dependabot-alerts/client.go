package da

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	gh "github.com/cli/go-gh"
	dg "github.com/steiza/gh-dependabot/pkg/dependency-graph"
)

type Dependency struct {
	ManifestPath string `json:"manifest_path"`
}

type SecurityAdvisory struct {
	Summary string
}

type Package struct {
	Ecosystem string
	Name      string
}

type FirstPatchedVersion struct {
	Identifier string
}

type SecurityVulnerability struct {
	Severity            string
	Package             Package
	FirstPatchedVersion FirstPatchedVersion `json:"first_patched_version"`
}

type AlertResponse struct {
	Number                int
	State                 string
	Dependency            Dependency
	SecurityAdvisory      SecurityAdvisory      `json:"security_advisory"`
	SecurityVulnerability SecurityVulnerability `json:"security_vulnerability"`
}

type Finding struct {
	Name               string
	Ecosystem          string
	ManifestPath       string
	ManifestVersion    string
	TopSummary         string
	TopSummarySeverity int
	TopPatchedVersion  string
	Count              int
}

type Findings []Finding

func (f Findings) Len() int {
	return len(f)
}

func (f Findings) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func (f Findings) Less(i, j int) bool {
	if f[i].TopSummarySeverity == f[j].TopSummarySeverity {
		return f[i].Count < f[j].Count
	}

	return f[i].TopSummarySeverity < f[j].TopSummarySeverity
}

func (f Finding) PackageString() string {
	return f.Name + " (" + f.Ecosystem + ")"
}

func (f Finding) UsageString() string {
	return f.ManifestVersion + " (" + f.ManifestPath + ")"
}

func (f Finding) SummaryString() string {
	if f.Count == 1 {
		return f.TopSummary
	} else {
		return fmt.Sprintf("(+ %d) %s", f.Count, f.TopSummary)
	}
}

func semverLess(i, j string) bool {
	r, _ := regexp.Compile("[0-9]+(\\.[0-9a-zA-Z]+)+")

	iSemver := strings.SplitN(r.FindString(i), ".", 3)
	jSemver := strings.SplitN(r.FindString(j), ".", 3)

	for k := 0; k < 3; k++ {
		iVal, err := strconv.ParseInt(iSemver[k], 0, 64)
		if err != nil {
			return true
		}

		jVal, err := strconv.ParseInt(jSemver[k], 0, 64)
		if err != nil {
			return false
		}

		if iVal < jVal {
			return true
		} else if iVal > jVal {
			return false
		}
	}

	return false
}

func sevStrToInt(sev string) int {
	if sev == "critical" {
		return 4
	} else if sev == "high" {
		return 3
	} else if sev == "medium" {
		return 2
	}
	return 1
}

func SevIntToStr(sev int) string {
	// These are purposefully abbreviated for terminal output
	if sev == 4 {
		return "crit"
	} else if sev == 3 {
		return "high"
	} else if sev == 2 {
		return "med"
	}
	return "low"
}

var linkRE = regexp.MustCompile(`<([^>]+)>;\s*rel="([^"]+)"`)
var urlPath *string

func findNextPage(resp *http.Response) (string, bool) {
	for _, m := range linkRE.FindAllStringSubmatch(resp.Header.Get("Link"), -1) {
		if len(m) > 2 && m[2] == "next" {
			return m[1], true
		}
	}
	return "", false
}

func GetFindings(repoOwner, repoName string, dependencyMap dg.DependencyMap) Findings {
	findings := make(map[string]Finding)

	client, err := gh.RESTClient(nil)
	if err != nil {
		log.Fatal(err)
	}

	alertResponses := []AlertResponse{}

	params := url.Values{}
	params.Add("state", "open")
	params.Add("per_page", "100")

	urlPathStr := "repos/" + repoOwner + "/" + repoName + "/dependabot/alerts?" + params.Encode()
	urlPath = &urlPathStr

	for {
		resp, err := client.Request("GET", *urlPath, nil)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		err = json.Unmarshal(body, &alertResponses)
		if err != nil {
			log.Fatal(err)
		}

		processFindings(alertResponses, dependencyMap, findings)
		urlPathStr, next := findNextPage(resp)
		urlPath = &urlPathStr

		if !next {
			break
		}
	}

	findingList := Findings{}
	for _, value := range findings {
		findingList = append(findingList, value)
	}
	sort.Reverse(findingList)

	return findingList
}

func processFindings(alertResponses []AlertResponse, dependencyMap dg.DependencyMap, findings map[string]Finding) {
	for _, value := range alertResponses {
		pkg := value.SecurityVulnerability.Package
		pkgName := strings.ToLower(pkg.Name)
		pkgEcosystem := strings.ToLower(pkg.Ecosystem)
		pkgKey := fmt.Sprintf("%s (%s)", pkgName, pkgEcosystem)

		sevInt := sevStrToInt(value.SecurityVulnerability.Severity)

		if finding, ok := findings[pkgKey]; ok {
			if sevInt > finding.TopSummarySeverity {
				finding.TopSummary = value.SecurityAdvisory.Summary
				finding.TopSummarySeverity = sevInt
			}
			if semverLess(finding.TopPatchedVersion, value.SecurityVulnerability.FirstPatchedVersion.Identifier) {
				finding.TopPatchedVersion = value.SecurityVulnerability.FirstPatchedVersion.Identifier
			}
			finding.Count += 1
			findings[pkgKey] = finding
		} else {
			version := dependencyMap[value.Dependency.ManifestPath][pkgEcosystem][pkgName]

			findings[pkgKey] = Finding{
				Name:               pkgName,
				Ecosystem:          pkgEcosystem,
				ManifestPath:       value.Dependency.ManifestPath,
				ManifestVersion:    version,
				TopSummary:         value.SecurityAdvisory.Summary,
				TopSummarySeverity: sevInt,
				TopPatchedVersion:  value.SecurityVulnerability.FirstPatchedVersion.Identifier,
				Count:              1,
			}
		}
	}
}
