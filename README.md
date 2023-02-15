# gh-dependabot

This [gh CLI extension](https://docs.github.com/en/github-cli/github-cli/using-github-cli-extensions) is for interacting with your [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) from the command line:

```
$ gh dependabot -r steiza/dependabot-example
Dependency     Has PR  Scope  Sev   Version            Summary
----           ----    ----   ----  ----               ----
urllib3 (pip)  N       dev    high  1.25.10 -> 1.26.5  Catastrophic backtracking in URL authority parser when passed ...
pillow (pip)   Y       run    crit  8.1.0 -> 9.2.0     (+ 23) Out-of-bounds Read
```

It aggregates Dependabot alerts for the same dependency and ecosystem, and attempts to determine what version of the dependency you're currently using.

There's also an interactive interface:

```
$ gh dependabot -r steiza/dependabot-example -i

                           Dependabot Alerts for steiza/dependabot-example

  pillow (pip)                                    ┌───────────────────────────────────────────────┐
  8.1.0 -> 9.2.0                                  │                                               │
  urllib3 (pip)                                   │  Package:  pillow (pip)                       │
  1.25.10 -> 1.26.5                               │                                               │
                                                  │  Has PR:   Y                                  │
                                                  │                                               │
                                                  │  Scope:    runtime                            │
                                                  │                                               │
                                                  │  Severity: crit                               │
                                                  │                                               │
                                                  │  Summary:                                     │
                                                  │                                               │
                                                  │  (+ 23) Out-of-bounds Read                    │
                                                  │                                               │
                                                  │  Usage:    8.1.0 -> 9.2.0                     │
                                                  │                                               │
                                                  └───────────────────────────────────────────────┘

                q: quit   a: view alerts in browser   p: view pull request in browser
```

If output is redirected, it will use the JSON it got back from the GitHub API, which could be useful for debugging:

```
$ gh dependabot -r steiza/dependabot-example | jq
[
  {
    "DependabotUpdate": {
      "PullRequest": {
...
```
