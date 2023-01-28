# gh-dependabot

This [gh CLI extension](https://docs.github.com/en/github-cli/github-cli/using-github-cli-extensions) is for interacting with your [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) from the command line:

```
$ gh dependabot --repo octocat/example-repo
Dependency     Summary                                Sev   Usage                            Upgrade
----           ----                                   ----  ----                             ----
pillow (pip)   (+ 23) Arbitrary expression inject...  crit  8.1.0 (requirements.txt)         9.2.0
urllib3 (pip)  Catastrophic backtracking in URL a...  high  1.25.10 (test-requirements.txt)  1.26.5
```

It aggregates Dependabot alerts for the same dependency and ecosystem, and attempts to determine what version of the dependency you're currently using.
