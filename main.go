package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	gh "github.com/cli/go-gh"
	"github.com/cli/go-gh/pkg/browser"
	"github.com/cli/go-gh/pkg/repository"
	"github.com/cli/go-gh/pkg/tableprinter"
	"github.com/cli/go-gh/pkg/term"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	da "github.com/steiza/gh-dependabot/pkg/dependabot-alerts"
	dg "github.com/steiza/gh-dependabot/pkg/dependency-graph"
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

	dependencies := dg.GetDependencies(repo.Owner(), repo.Name())
	findings := da.GetFindings(repo.Owner(), repo.Name(), dependencies)

	if *interactive {
		app := tview.NewApplication()

		details := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true)
		details.SetBorder(true).SetBorderColor(tcell.ColorGreen)

		depList := tview.NewList()
		for _, value := range findings {
			depList.AddItem(value.PackageString(), "  "+value.UsageString()+" -> "+value.TopPatchedVersion, rune(0), nil)
		}

		depListChangedFunc := func(index int, mainText, secondaryText string, shortcut rune) {
			if index > len(findings) {
				details.SetText("")
			} else {
				item := findings[index]
				details.SetText("\n  [green]Package:[white]  " + item.PackageString() + "\n\n  [green]Severity:[white] " + da.SevIntToStr(item.TopSummarySeverity) + "\n\n  [green]Summary:[white]\n\n  " + item.SummaryString() + "\n\n  [green]Usage:[white]    " + item.UsageString() + "\n\n  [green]Upgrade:[white]  " + item.TopPatchedVersion)
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
				item := findings[index]

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

		for _, value := range findings {
			t.AddField(value.PackageString())
			t.AddField(value.SummaryString())
			t.AddField(da.SevIntToStr(value.TopSummarySeverity))
			t.AddField(value.UsageString())
			t.AddField(value.TopPatchedVersion)
			t.EndRow()
		}

		if err = t.Render(); err != nil {
			log.Fatal(err)
		}
	}
}
