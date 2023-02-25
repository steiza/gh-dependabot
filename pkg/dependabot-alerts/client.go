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
	graphql "github.com/cli/shurcooL-graphql"
)

type Package struct {
	Ecosystem string
	Name      string
}

type FirstPatchedVersion struct {
	Identifier string
}

type SecurityVulnerability struct {
	FirstPatchedVersion FirstPatchedVersion
	Package             Package
	Severity            string
}

type SecurityAdvisory struct {
	Summary string
}

type Node struct {
	DependabotUpdate struct {
		PullRequest struct {
			ResourcePath string
			State        string
		}
	}
	DependencyScope  string
	Number           int
	SecurityAdvisory struct {
		Summary string
	}
	SecurityVulnerability  SecurityVulnerability
	State                  string
	VulnerableManifestPath string
	VulnerableRequirements string
}

type VulnerabilityAlerts struct {
	Nodes    []Node
	PageInfo struct {
		HasNextPage bool
		EndCursor   string
	}
}

type Repository struct {
	VulnerabilityAlerts VulnerabilityAlerts `graphql:"vulnerabilityAlerts(first: $first, after: $cursor, states:OPEN)"`
}

type Query struct {
	Repository Repository `graphql:"repository(name: $name, owner: $owner)"`
}

type CompatabilityResponse struct {
	Data struct {
		Attributes struct {
			Status string
		}
	}
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
	DependencyScope    string
	PullRequestURL     string
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

func (f Finding) VersionString() string {
	return fmt.Sprintf("%s -> %s", strings.SplitAfter(f.ManifestVersion, " ")[1], f.TopPatchedVersion)
}

func (f Finding) HasPR() string {
	if f.PullRequestURL != "" {
		return "Y"
	} else {
		return "N"
	}
}

func (f Finding) GetCompatability() string {
	client := &http.Client{}

	packageManager := f.Ecosystem
	if packageManager == "go" {
		packageManager = "go_modules"
	}

	values := url.Values{
		"dependency-name":  {f.Name},
		"package-manager":  {packageManager},
		"previous-version": {f.ManifestVersion},
		"new-version":      {f.TopPatchedVersion},
	}

	req, err := http.NewRequest("GET", "https://dependabot-badges.githubapp.com/badges/compatibility_score?"+values.Encode(), nil)
	if err != nil {
		log.Print("Unable to create compatability request")
		return "unknown"
	}

	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Print("Unable to reach compatability endpoint")
		return "unknown"
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Print("Unable to read compatability response")
		return "unknown"
	}

	compatability := CompatabilityResponse{}
	err = json.Unmarshal(body, &compatability)
	if err != nil {
		log.Print("Unable to parse compatability response")
		return "unknown"
	}

	return compatability.Data.Attributes.Status
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
	if sev == "CRITICAL" {
		return 4
	} else if sev == "HIGH" {
		return 3
	} else if sev == "MEDIUM" {
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

var urlPath *string

func GetNodes(repoOwner, repoName string) []Node {
	var nodes []Node

	client, err := gh.GQLClient(nil)
	if err != nil {
		log.Fatal(err)
	}

	var cursor *graphql.String
	for {
		var query Query

		variables := map[string]interface{}{
			"name":   graphql.String(repoName),
			"owner":  graphql.String(repoOwner),
			"first":  graphql.Int(100),
			"cursor": cursor,
		}

		err := client.Query("DependabotAlerts", &query, variables)
		if err != nil {
			log.Fatal(err)
		}

		nodes = append(nodes, query.Repository.VulnerabilityAlerts.Nodes...)

		cursor = (*graphql.String)(&query.Repository.VulnerabilityAlerts.PageInfo.EndCursor)
		if !query.Repository.VulnerabilityAlerts.PageInfo.HasNextPage {
			break
		}
	}

	return nodes
}

func GetFindings(repoOwner, repoName string) Findings {
	nodes := GetNodes(repoOwner, repoName)
	findings := make(map[string]Finding)

	processFindings(nodes, findings)

	findingList := Findings{}
	for _, value := range findings {
		findingList = append(findingList, value)
	}
	sort.Reverse(findingList)

	return findingList
}

func processFindings(nodes []Node, findings map[string]Finding) {
	for _, node := range nodes {
		pkg := node.SecurityVulnerability.Package
		pkgName := strings.ToLower(pkg.Name)
		pkgEcosystem := strings.ToLower(pkg.Ecosystem)
		pkgKey := fmt.Sprintf("%s (%s)", pkgName, pkgEcosystem)

		sevInt := sevStrToInt(node.SecurityVulnerability.Severity)

		if finding, ok := findings[pkgKey]; ok {
			if sevInt > finding.TopSummarySeverity {
				finding.TopSummary = node.SecurityAdvisory.Summary
				finding.TopSummarySeverity = sevInt
			}
			if semverLess(finding.TopPatchedVersion, node.SecurityVulnerability.FirstPatchedVersion.Identifier) {
				finding.TopPatchedVersion = node.SecurityVulnerability.FirstPatchedVersion.Identifier
			}
			if node.DependabotUpdate.PullRequest.State == "OPEN" {
				finding.PullRequestURL = node.DependabotUpdate.PullRequest.ResourcePath
			}
			finding.Count += 1
			findings[pkgKey] = finding
		} else {
			finding = Finding{
				Name:               pkgName,
				Ecosystem:          pkgEcosystem,
				ManifestPath:       node.VulnerableManifestPath,
				ManifestVersion:    node.VulnerableRequirements,
				TopSummary:         node.SecurityAdvisory.Summary,
				TopSummarySeverity: sevInt,
				TopPatchedVersion:  node.SecurityVulnerability.FirstPatchedVersion.Identifier,
				Count:              1,
				DependencyScope:    node.DependencyScope,
			}

			if node.DependabotUpdate.PullRequest.State == "OPEN" {
				finding.PullRequestURL = node.DependabotUpdate.PullRequest.ResourcePath
			}

			findings[pkgKey] = finding
		}
	}
}
