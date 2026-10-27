# Approves a parked team run and resumes it.
#
# Same reasoning as scripts/hunt-approve.ps1: Windows PowerShell 5.1 mangles
# nested arrays in ConvertTo-Json, so the parked file's argv is pasted verbatim
# into the request body rather than rebuilt.
param(
    [Parameter(Mandatory = $true)][string]$Parked,
    [string]$DecidedBy = 'analyst-zhang'
)

$ErrorActionPreference = 'Continue'
$env:SOC_PG_DSN = 'postgres://soc:soc-local-dev-only@127.0.0.1:5432/soc?sslmode=disable'
$env:SOC_MODELS_CONFIG = 'models.yaml'
$env:SOC_EXEC_BACKEND = 'docker'
$env:SOC_TOOLBOX_CONTAINER = 'soc-toolbox'

$state = Get-Content $Parked -Raw -Encoding utf8 | ConvertFrom-Json

$parts = foreach ($item in $state.argv) {
    '"' + ($item -replace '\\', '\\' -replace '"', '\"') + '"'
}
$argvJson = '[' + ($parts -join ',') + ']'

$target = $state.target + ':' + $state.port
$request = '{"scope_id":"' + $state.scope_id + '","target":"' + $target + '"' +
    ',"argv":' + $argvJson + ',"risk":"active"' +
    ',"requested_by":"analyst-zhang","ttl_minutes":30}'
$requestFile = Join-Path $env:TEMP 'team-approval.json'
[System.IO.File]::WriteAllText($requestFile, $request, [System.Text.UTF8Encoding]::new($false))

$created = curl.exe -s -X POST http://127.0.0.1:8080/api/v1/approvals -H 'Content-Type: application/json' --data-binary "@$requestFile" | ConvertFrom-Json
if ($created.approval.id) {
    $approvalId = $created.approval.id
} elseif ($created.id) {
    $approvalId = $created.id
} else {
    Write-Output ('approval request failed: ' + ($created | ConvertTo-Json -Compress -Depth 4))
    exit 1
}
Write-Output ('approval_code=' + $created.code)
Write-Output ('approval_id=' + $approvalId)

$decideFile = Join-Path $env:TEMP 'team-decide.json'
[System.IO.File]::WriteAllText($decideFile, '{"decision":"approved","decided_by":"' + $DecidedBy + '","reason":"authorized CTF engagement"}', [System.Text.UTF8Encoding]::new($false))
$decided = curl.exe -s -X POST "http://127.0.0.1:8080/api/v1/approvals/$approvalId/decide" -H 'Content-Type: application/json' --data-binary "@$decideFile" | ConvertFrom-Json
Write-Output ('decision=' + $decided.approval.decision)

Write-Output '--- resuming team ---'
& go run ./cmd/soc team --resume $Parked --approval $approvalId 2>&1 | Out-String
