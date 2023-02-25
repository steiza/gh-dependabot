# gh-dependabot

You can install this extension with `$ gh ext install steiza/gh-dependabot`.

A [gh CLI extension](https://docs.github.com/en/github-cli/github-cli/using-github-cli-extensions) for interacting with your [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) and [Dependabot security updates](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates) from the command line.

## Dependabot alerts

First up, Dependabot alerts:

```
$ gh dependabot alerts -r steiza/dependabot-example
pillow (pip)   /steiza/dependabot-example/pull/2  run  crit  8.1.0 -> 9.2.0     (+ 23) Out-of-bounds Read
urllib3 (pip)  /steiza/dependabot-example/pull/1  dev  high  1.25.10 -> 1.26.5  Catastrophic backtracking in URL auth...
```

Alerts are aggregated by dependency and ecosystem, with information about runtime or development dependendies, as well as what version you're currently using.

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

## Dependabot security updates

You can also land pending Dependabot security updates:

```
$ gh dependabot updates -r steiza/dependabot-example -m
https://github.com/steiza/dependabot-example/pull/2  75%  pillow (pip)   8.1.0 -> 9.2.0
https://github.com/steiza/dependabot-example/pull/1  66%  urllib3 (pip)  1.25.10 -> 1.26.5
? Merge 2 pull requests? Yes
Merging 2 pull requests
Working on https://github.com/steiza/dependabot-example/pull/2
        Pull Request successfully merged
Working on https://github.com/steiza/dependabot-example/pull/1
        Waiting for pull request to be mergable
        Pull Request successfully merged
```

This could be useful if you lots of pending pull requests, or if you want to automate landing these pull requests (see `--yes`).
