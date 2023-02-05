package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cli/go-gh"
	"github.com/cli/go-gh/pkg/api"
	"github.com/cli/go-gh/pkg/browser"
	"github.com/cli/go-gh/pkg/repository"
	"github.com/cli/go-gh/pkg/tableprinter"
	"github.com/cli/go-gh/pkg/term"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func semverLess(i, j string) bool {
	iSemver := strings.SplitN(i, ".", 3)
	jSemver := strings.SplitN(j, ".", 3)

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

func contentToVersion(content string, packageName string) string {
	r, _ := regexp.Compile("(?i).*" + packageName + ".*")
	lineMatch := r.FindString(content)
	lineMatch = strings.Trim(lineMatch, "\n")

	r, _ = regexp.Compile("[0-9]+(\\.[0-9a-zA-Z]+)+")
	return r.FindString(lineMatch)
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

func sevIntToStr(sev int) string {
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
	Package             Package
	Severity            string
	FirstPatchedVersion FirstPatchedVersion `json:"first_patched_version"`
}

type DependabotResponse struct {
	Number                int
	State                 string
	Dependency            Dependency
	SecurityAdvisory      SecurityAdvisory      `json:"security_advisory"`
	SecurityVulnerability SecurityVulnerability `json:"security_vulnerability"`
}

func getContents(client api.RESTClient, repoOwner string, repoName string, manifestPath string) string {
	contentResponse := struct {
		Encoding string
		Content  string
	}{}

	err := client.Get("repos/"+repoOwner+"/"+repoName+"/contents/"+manifestPath, &contentResponse)
	if err != nil {
		log.Fatal(err)
	}

	content, err := base64.StdEncoding.DecodeString(contentResponse.Content)
	if err != nil {
		log.Fatal(err)
	}

	return string(content)
}

func processFindings(client api.RESTClient, owner string, name string, dependabotResponses []DependabotResponse, getContents func(api.RESTClient, string, string, string) string, findings map[string]Finding) {
	for _, value := range dependabotResponses {
		pkg := value.SecurityVulnerability.Package
		pkgString := fmt.Sprintf("%s (%s)", strings.ToLower(pkg.Name), pkg.Ecosystem)

		valueSev := sevStrToInt(value.SecurityVulnerability.Severity)

		if finding, ok := findings[pkgString]; ok {
			if valueSev > finding.TopSummarySeverity {
				finding.TopSummary = value.SecurityAdvisory.Summary
				finding.TopSummarySeverity = valueSev
			}
			if semverLess(finding.TopPatchedVersion, value.SecurityVulnerability.FirstPatchedVersion.Identifier) {
				finding.TopPatchedVersion = value.SecurityVulnerability.FirstPatchedVersion.Identifier
			}
			finding.Count += 1
			findings[pkgString] = finding
		} else {
			// Find out what version we're using by querying content API
			content := getContents(client, owner, name, value.Dependency.ManifestPath)
			version := contentToVersion(content, pkg.Name)

			findings[pkgString] = Finding{
				Name:               strings.ToLower(pkg.Name),
				Ecosystem:          pkg.Ecosystem,
				ManifestPath:       value.Dependency.ManifestPath,
				ManifestVersion:    version,
				TopSummary:         value.SecurityAdvisory.Summary,
				TopSummarySeverity: valueSev,
				TopPatchedVersion:  value.SecurityVulnerability.FirstPatchedVersion.Identifier,
				Count:              1,
			}
		}
	}
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

func main() {
	client, err := gh.RESTClient(nil)
	if err != nil {
		log.Fatal(err)
	}

	repoOverride := flag.String("repo", "r", "Repository to query. Current directory used by default.")
	interactive := flag.Bool("interactive", false, "Interact with results in the terminal.")
	flag.Parse()

	var repo repository.Repository

	if *repoOverride == "" {
		repo, err = gh.CurrentRepository()
	} else {
		repo, err = repository.Parse(*repoOverride)
	}

	if err != nil {
		log.Fatal(err)
	}

	dependabotResponse := []DependabotResponse{}

	params := url.Values{}
	params.Add("state", "open")
	params.Add("per_page", "100")

	urlPathStr := "repos/" + repo.Owner() + "/" + repo.Name() + "/dependabot/alerts?" + params.Encode()
	urlPath = &urlPathStr

	findings := make(map[string]Finding)

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

		err = json.Unmarshal(body, &dependabotResponse)
		if err != nil {
			log.Fatal(err)
		}

		processFindings(client, repo.Owner(), repo.Name(), dependabotResponse, getContents, findings)
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

	if *interactive {
		app := tview.NewApplication()

		details := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true)
		details.SetBorder(true).SetBorderColor(tcell.ColorGreen)

		depList := tview.NewList()
		for _, value := range findingList {
			depList.AddItem(value.PackageString(), "  "+value.UsageString()+" -> "+value.TopPatchedVersion, rune(0), nil)
		}

		depListChangedFunc := func(index int, mainText, secondaryText string, shortcut rune) {
			if index > len(findingList) {
				details.SetText("")
			} else {
				item := findingList[index]
				details.SetText("\n  [green]Package:[white]  " + item.PackageString() + "\n\n  [green]Severity:[white] " + sevIntToStr(item.TopSummarySeverity) + "\n\n  [green]Summary:[white]\n\n  " + item.SummaryString() + "\n\n  [green]Usage:[white]    " + item.UsageString() + "\n\n  [green]Upgrade:[white]  " + item.TopPatchedVersion)
			}
		}

		depListChangedFunc(0, "", "", rune(0))
		depList.SetChangedFunc(depListChangedFunc)

		flex := tview.NewFlex().AddItem(depList, 0, 1, true).AddItem(details, 0, 1, false)

		frame := tview.NewFrame(flex).SetBorders(1, 1, 1, 1, 0, 0)
		frame.AddText("Dependabot Alerts for "+repo.Owner()+"/"+repo.Name(), true, tview.AlignCenter, tcell.ColorWhite)
		frame.AddText("q: quit   a: open alerts in browser", false, tview.AlignCenter, tcell.ColorWhite)

		app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			switch event.Rune() {
			case 'q':
				app.Stop()

			case 'a':
				index := depList.GetCurrentItem()
				item := findingList[index]

				params := url.Values{}
				params.Add("q", fmt.Sprintf("is:open package:%s ecosystem:%s", item.Name, item.Ecosystem))
				url := "https://" + repo.Host() + "/" + repo.Owner() + "/" + repo.Name() + "/security/dependabot?" + params.Encode()
				b := browser.New("", os.Stdout, os.Stderr)
				err = b.Browse(url)
				if err != nil {
					log.Println(err)
				}
			}

			return event
		})

		err := app.SetRoot(frame, true).Run()
		if err != nil {
			log.Fatal(err)
		}

	} else {
		// Print out findings
		terminal := term.FromEnv()
		termWidth, _, _ := terminal.Size()
		t := tableprinter.New(terminal.Out(), terminal.IsTerminalOutput(), termWidth)

		t.AddField("Dependency")
		t.AddField("Summary")
		t.AddField("Sev")
		t.AddField("Usage")
		t.AddField("Upgrade")
		t.EndRow()
		t.AddField("----")
		t.AddField("----")
		t.AddField("----")
		t.AddField("----")
		t.AddField("----")
		t.EndRow()

		for _, value := range findingList {
			t.AddField(value.PackageString())
			t.AddField(value.SummaryString())
			t.AddField(sevIntToStr(value.TopSummarySeverity))
			t.AddField(value.UsageString())
			t.AddField(value.TopPatchedVersion)
			t.EndRow()
		}

		if err = t.Render(); err != nil {
			log.Fatal(err)
		}
	}
}
