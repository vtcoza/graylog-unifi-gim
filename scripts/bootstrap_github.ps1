param(
    [string]$Repository = "vtcoza/graylog-unifi-gim"
)

$ErrorActionPreference = "Stop"
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is required. Install it and run 'gh auth login' first."
}

$spec = Get-Content -Raw -LiteralPath "$PSScriptRoot\..\github\project-seed.json" | ConvertFrom-Json
gh repo view $Repository *> $null
if ($LASTEXITCODE -ne 0) {
    gh repo create $Repository --public --source "$PSScriptRoot\.." --remote origin --description "UniFi OS CEF/syslog integration normalized to Graylog GIM"
}

foreach ($label in $spec.labels) {
    gh label create $label --repo $Repository --force *> $null
}

foreach ($milestone in $spec.milestones) {
    $body = @{title = $milestone.title; description = $milestone.description} | ConvertTo-Json -Compress
    $body | gh api --method POST "repos/$Repository/milestones" --input - *> $null
}

foreach ($issue in $spec.initial_issues) {
    $labels = $issue.labels -join ","
    gh issue create --repo $Repository --title $issue.title --milestone $issue.milestone --label $labels --body "Seeded from github/project-seed.json."
}

Write-Output "GitHub repository metadata initialized for $Repository"
