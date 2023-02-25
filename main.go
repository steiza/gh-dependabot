package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	gh "github.com/cli/go-gh"
	"github.com/cli/go-gh/pkg/browser"
	"github.com/cli/go-gh/pkg/repository"
	"github.com/cli/go-gh/pkg/tableprinter"
	"github.com/cli/go-gh/pkg/term"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"

	da "github.com/steiza/gh-dependabot/pkg/dependabot-alerts"
	"github.com/steiza/gh-dependabot/pkg/pulls"
)

var repoOverride string
var interactive, merge, yes bool

func runAlertsCmd(cmd *cobra.Command, args []string) error {
	var repo repository.Repository
	var err error

	if repoOverride == "" {
		repo, err = gh.CurrentRepository()
	} else {
		repo, err = repository.Parse(repoOverride)
	}

	if err != nil {
		return err
	}

	terminal := term.FromEnv()
	if !terminal.IsTerminalOutput() {
		nodes := da.GetNodes(repo.Owner(), repo.Name())
		jsonBytes, err := json.Marshal(nodes)
		if err != nil {
			return err
		}
		fmt.Print(string(jsonBytes))
		return nil
	}

	findings := da.GetFindings(repo.Owner(), repo.Name())

	if len(findings) == 0 {
		fmt.Println("No Dependabot Alerts found")
		return nil
	}

	if interactive {
		app := tview.NewApplication()

		details := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true)
		details.SetBorder(true).SetBorderColor(tcell.ColorGreen)

		depList := tview.NewList()
		for _, value := range findings {
			depList.AddItem(value.PackageString(), value.VersionString(), rune(0), nil)
		}

		flex := tview.NewFlex().AddItem(depList, 0, 1, true).AddItem(details, 0, 1, false)

		frame := tview.NewFrame(flex).SetBorders(1, 1, 1, 1, 0, 0)
		frame.AddText("Dependabot Alerts for "+repo.Owner()+"/"+repo.Name(), true, tview.AlignCenter, tcell.ColorWhite)
		frame.AddText("q: quit   a: view alerts in browser   p: view pull request in browser", false, tview.AlignCenter, tcell.ColorWhite)

		depListChangedFunc := func(index int, mainText, secondaryText string, shortcut rune) {
			if index > len(findings) {
				details.SetText("")
			} else {
				item := findings[index]
				details.SetText("\n  [green]Package:[white]  " + item.PackageString() + "\n\n  [green]Has PR:[white]   " + item.HasPR() + "\n\n  [green]Scope:[white]    " + strings.ToLower(item.DependencyScope) + "\n\n  [green]Severity:[white] " + da.SevIntToStr(item.TopSummarySeverity) + "\n\n  [green]Summary:[white]\n\n  " + item.SummaryString() + "\n\n  [green]Usage:[white]    " + item.VersionString())

				frame.Clear()
				frame.AddText("Dependabot Alerts for "+repo.Owner()+"/"+repo.Name(), true, tview.AlignCenter, tcell.ColorWhite)
				if item.PullRequestURL != "" {
					frame.AddText("q: quit   a: view alerts in browser   p: view pull request in browser", false, tview.AlignCenter, tcell.ColorWhite)
				} else {
					frame.AddText("q: quit   a: view alerts in browser", false, tview.AlignCenter, tcell.ColorWhite)
				}

			}
		}

		depListChangedFunc(0, "", "", rune(0))
		depList.SetChangedFunc(depListChangedFunc)

		app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			switch event.Rune() {
			case 'q':
				app.Stop()

			case 'a':
				index := depList.GetCurrentItem()
				item := findings[index]

				params := url.Values{}
				params.Add("q", fmt.Sprintf("is:open package:%s ecosystem:%s", item.Name, item.Ecosystem))
				url := "https://" + repo.Host() + "/" + repo.Owner() + "/" + repo.Name() + "/security/dependabot?" + params.Encode()
				b := browser.New("", os.Stdout, os.Stderr)
				err = b.Browse(url)
				if err != nil {
					log.Println(err)
				}

			case 'p':
				index := depList.GetCurrentItem()
				item := findings[index]

				if item.PullRequestURL != "" {
					url := "https://" + repo.Host() + item.PullRequestURL
					b := browser.New("", os.Stdout, os.Stderr)
					err = b.Browse(url)
					if err != nil {
						log.Println(err)
					}
				}
			}

			return event
		})

		err := app.SetRoot(frame, true).Run()
		if err != nil {
			return err
		}

	} else {
		// Print out findings
		termWidth, _, _ := terminal.Size()
		t := tableprinter.New(terminal.Out(), terminal.IsTerminalOutput(), termWidth)

		for _, value := range findings {
			t.AddField(value.PackageString())
			t.AddField(value.PullRequestURL)
			t.AddField(strings.ToLower(value.DependencyScope[:3]))
			t.AddField(da.SevIntToStr(value.TopSummarySeverity))
			t.AddField(value.VersionString())
			t.AddField(value.SummaryString())
			t.EndRow()
		}

		if err = t.Render(); err != nil {
			return err
		}
	}

	return nil
}

func runUpdatesCmd(cmd *cobra.Command, args []string) error {
	var repo repository.Repository
	var err error

	if repoOverride == "" {
		repo, err = gh.CurrentRepository()
	} else {
		repo, err = repository.Parse(repoOverride)
	}

	if err != nil {
		return err
	}

	findings := da.GetFindings(repo.Owner(), repo.Name())

	terminal := term.FromEnv()
	termWidth, _, _ := terminal.Size()
	t := tableprinter.New(terminal.Out(), terminal.IsTerminalOutput(), termWidth)

	prUrls := []string{}
	for _, value := range findings {
		if value.PullRequestURL == "" {
			continue
		}

		prUrl := "https://" + repo.Host() + value.PullRequestURL
		prUrls = append(prUrls, prUrl)

		t.AddField(prUrl)
		t.AddField(value.GetCompatability())
		t.AddField(value.PackageString())
		t.AddField(value.VersionString())
		t.EndRow()
	}

	if err = t.Render(); err != nil {
		return err
	}

	if len(prUrls) == 0 {
		fmt.Println("No pull requests found")
	}

	if !merge || len(prUrls) == 0 {
		// If we aren't merging, or if there aren't any PRs to merge, we're done!
		return nil
	}

	if !yes {
		// Confirm intent to merge pull requests
		prompt := &survey.Confirm{
			Message: fmt.Sprintf("Merge %d pull requests?", len(prUrls)),
		}

		confirm := false
		survey.AskOne(prompt, &confirm)

		if !confirm {
			return nil
		}
	}

	fmt.Printf("Merging %d pull requests\n", len(prUrls))

	client, err := gh.RESTClient(nil)
	if err != nil {
		log.Fatal(err)
	}

	for _, prUrl := range prUrls {
		fmt.Printf("Working on %s\n", prUrl)

		pull := pulls.Pull{}
		prUrlParts := strings.Split(prUrl, "/")
		prNumber := prUrlParts[len(prUrlParts)-1]
		pulls.GetPullRequest(client, repo.Owner(), repo.Name(), prNumber, &pull)

		if pull.State != "open" {
			fmt.Printf("\tPull request state is %s; skipping\n", pull.State)
			continue
		}

		if !pull.Mergeable {
			fmt.Println("\tWaiting for pull request to be mergable")
			mergable := pulls.WaitForMergable(client, repo.Owner(), repo.Name(), prNumber)
			if !mergable {
				fmt.Println("\tPull request not mergable; skipping")
			}
		}

		merge := pulls.Merge{}
		pulls.MergePullRequest(client, repo.Owner(), repo.Name(), prNumber, &merge)
		fmt.Printf("\t%s\n", merge.Message)
	}

	return nil
}

func main() {
	depCmd := cobra.Command{
		Use:     "dependabot",
		Short:   "Manage Dependabot alerts and updates",
		Aliases: []string{"dep", "depbot"},
	}

	depAlertsCmd := cobra.Command{
		Use:     "alerts",
		Short:   "Summarize Dependabot alerts by dependency",
		Aliases: []string{"alert", "a"},
		RunE:    runAlertsCmd,
	}

	depAlertsCmd.Flags().StringVarP(&repoOverride, "repository", "r", "", "Repository to query. Current directory is used by default.")
	depAlertsCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interact with results in the terminal.")
	depCmd.AddCommand(&depAlertsCmd)

	depUpdatesCmd := cobra.Command{
		Use:     "updates",
		Short:   "View and merge Dependabot updates pull requests",
		Aliases: []string{"update", "u"},
		RunE:    runUpdatesCmd,
	}

	depUpdatesCmd.Flags().StringVarP(&repoOverride, "repository", "r", "", "Repository to query. Current directory is used by default.")
	depUpdatesCmd.Flags().BoolVarP(&merge, "merge", "m", false, "Select Dependabot updates to merge.")
	depUpdatesCmd.Flags().BoolVarP(&yes, "yes", "y", false, "Merge Dependabot updates without prompting for confirmation.")
	depCmd.AddCommand(&depUpdatesCmd)

	depCmd.Execute()
}
