$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$latest = Get-Content -LiteralPath (Join-Path $projectRoot 'demo\latest.json') -Raw | ConvertFrom-Json
$global:KeywallDemoExe = Join-Path $projectRoot 'dist\keywall-win-x64\keywall.exe'
$global:KeywallDemoVault = $latest.vault
function global:kwdemo { & $global:KeywallDemoExe --vault $global:KeywallDemoVault @args }
$host.UI.RawUI.WindowTitle = 'Keywall — demo results (fake keys only)'
Write-Host 'KEYWALL DEMO — FAKE KEYS ONLY' -ForegroundColor Cyan
Get-Content -LiteralPath $latest.report | ForEach-Object {
    $color = if ($_ -match 'BLOCK|Blocked:') { 'Red' } elseif ($_ -match 'Verified:|No findings') { 'Green' } else { 'White' }
    Write-Host $_ -ForegroundColor $color
}
if ($latest.interactiveReveal) { Write-Host "`nInteractive plaintext extraction was also verified in a PTY terminal." -ForegroundColor Green }
Write-Host "`nTry these commands in this terminal:" -ForegroundColor Cyan
Write-Host 'kwdemo find demo'
Write-Host 'kwdemo reveal demo/test'
Write-Host ('kwdemo scan "' + (Join-Path $latest.directory 'leaked.env') + '"')
Write-Host ("Demo master phrase: " + $latest.masterPhrase) -ForegroundColor Yellow
Write-Host 'For reveal, enter REVEAL at the confirmation prompt.'
Write-Host 'The demo vault is separate from your personal vault; no real upload was performed.'
Set-Location -LiteralPath $latest.directory
