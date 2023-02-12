package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	gh "github.com/cli/go-gh"
	"github.com/cli/go-gh/pkg/browser"
	"github.com/cli/go-gh/pkg/repository"
	"github.com/cli/go-gh/pkg/tableprinter"
	"github.com/cli/go-gh/pkg/term"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	da "github.com/steiza/gh-dependabot/pkg/dependabot-alerts"
)

func main() {
	repoOverride := flag.String("repo", "r", "Repository to query. Current directory used by default.")
	interactive := flag.Bool("interactive", false, "Interact with results in the terminal.")
	flag.Parse()

	var repo repository.Repository
	var err error

	if *repoOverride == "" {
		repo, err = gh.CurrentRepository()
	} else {
		repo, err = repository.Parse(*repoOverride)
	}

	if err != nil {
		log.Fatal(err)
	}

	findings := da.GetFindings(repo.Owner(), repo.Name())

	if *interactive {
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
				details.SetText("\n  [green]Package:[white]  " + item.PackageString() + "\n\n  [green]Has PR:[white]   " + item.HasPR() + "\n\n  [green]Scope:[white]    " + strings.ToLower(item.DependencyScope) + "\n\n  [green]Severity:[white] " + da.SevIntToStr(item.TopSummarySeverity) + "\n\n  [green]Summary:[white]\n\n  " + item.SummaryString() + "\n\n  [green]Usage:[white]    " + item.VersionString() + "\n\n  [green]Upgrade:[white]  " + item.TopPatchedVersion)

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
			log.Fatal(err)
		}

	} else {
		// Print out findings
		terminal := term.FromEnv()
		termWidth, _, _ := terminal.Size()
		t := tableprinter.New(terminal.Out(), terminal.IsTerminalOutput(), termWidth)

		t.AddField("Dependency")
		t.AddField("Has PR")
		t.AddField("Scope")
		t.AddField("Sev")
		t.AddField("Version")
		t.AddField("Summary")
		t.EndRow()
		t.AddField("----")
		t.AddField("----")
		t.AddField("----")
		t.AddField("----")
		t.AddField("----")
		t.AddField("----")
		t.EndRow()

		for _, value := range findings {
			t.AddField(value.PackageString())
			if value.PullRequestURL != "" {
				t.AddField("Y")
			} else {
				t.AddField("N")
			}
			t.AddField(strings.ToLower(value.DependencyScope[:3]))
			t.AddField(da.SevIntToStr(value.TopSummarySeverity))
			t.AddField(value.VersionString())
			t.AddField(value.SummaryString())
			t.EndRow()
		}

		if err = t.Render(); err != nil {
			log.Fatal(err)
		}
	}
}
