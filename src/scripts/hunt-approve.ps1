# Approves a parked hunt run and resumes it.
#
# Exists because Windows PowerShell 5.1 mangles nested arrays in ConvertTo-Json,
# which would send a body the API rightly rejects. The parked file already holds
# the exact argv, so it is pasted verbatim into the request body instead.
param(
    [Parameter(Mandatory = $true)][string]$Parked,
    [string]$DecidedBy = 'analyst-zhang'
)

$ErrorActionPreference = 'Continue'
$env:SOC_PG_DSN = 'postgres://soc:soc-local-dev-only@127.0.0.1:5432/soc?sslmode=disable'
$env:SOC_MODELS_CONFIG = 'models.yaml'

$state = Get-Content $Parked -Raw -Encoding utf8 | ConvertFrom-Json
$argvJson = ConvertTo-Json -InputObject @($state.argv) -Compress
if ($argvJson -notmatch '^\["') { $argvJson = '[' + (($state.argv | ForEach-Object { '"' + ($_ -replace '\\', '\\' -replace '"', '\"') + '"' }) -join ',') + ']' }

$request = '{"scope_id":"' + $state.scope_id + '","target":"' + $state.target + ':443"' +
    ',"argv":' + $argvJson + ',"risk":"' + $state.risk + '"' +
    ',"requested_by":"analyst-zhang","ttl_minutes":30}'
$requestFile = Join-Path $env:TEMP 'hunt-approval.json'
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

$decide = '{"decision":"approved","decided_by":"' + $DecidedBy + '","reason":"authorized CTF demo"}'
$decideFile = Join-Path $env:TEMP 'hunt-decide.json'
[System.IO.File]::WriteAllText($decideFile, $decide, [System.Text.UTF8Encoding]::new($false))
$decided = curl.exe -s -X POST "http://127.0.0.1:8080/api/v1/approvals/$approvalId/decide" -H 'Content-Type: application/json' --data-binary "@$decideFile" | ConvertFrom-Json
Write-Output ('decision=' + $decided.approval.decision)

Write-Output '--- resuming ---'
& go run ./cmd/soc hunt --resume $Parked --approval $approvalId 2>&1 | Out-String
