# gh-dependabot

This [gh CLI extension](https://docs.github.com/en/github-cli/github-cli/using-github-cli-extensions) is for interacting with your [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) from the command line:

```
$ gh dependabot --repo steiza/dependabot-example
Dependency     Summary                                Sev   Usage                            Upgrade
----           ----                                   ----  ----                             ----
pillow (pip)   (+ 23) Arbitrary expression inject...  crit  8.1.0 (requirements.txt)         9.2.0
urllib3 (pip)  Catastrophic backtracking in URL a...  high  1.25.10 (test-requirements.txt)  1.26.5
```

It aggregates Dependabot alerts for the same dependency and ecosystem, and attempts to determine what version of the dependency you're currently using.

There's also an interactive interface (`$ gh dependabot --repo steiza/dependabot-example --interactive`):

```
                          Dependabot Alerts for steiza/dependabot-example

urllib3 (pip)                                     ┌────────────────────────────────────────────────┐┐
  = 1.25.10 (test-requirements.txt) -> 1.26.5     │                                                ││
pillow (pip)                                      │  Package:  urllib3 (pip)                       ││
  = 8.1.0 (requirements.txt) -> 9.2.0             │                                                ││
                                                  │  Severity: high                                ││
                                                  │                                                ││
                                                  │  Summary:                                      ││
                                                  │                                                ││
                                                  │  Catastrophic backtracking in URL authority    ││
                                                  │parser when passed URL containing many @        ││
                                                  │characters                                      ││
                                                  │                                                ││
                                                  │  Usage:    = 1.25.10 (test-requirements.txt)   ││
                                                  │                                                ││
                                                  │  Upgrade:  1.26.5                              ││
                                                  │                                                ││
                                                  │                                                ││
                                                  └────────────────────────────────────────────────┘┘

                                q: quit   a: open alerts in browser
```
