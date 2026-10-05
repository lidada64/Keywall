param([switch]$InteractiveReveal)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$demoRoot = Join-Path $projectRoot ('demo\' + [DateTime]::Now.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6))
New-Item -ItemType Directory -Path $demoRoot -Force | Out-Null
$exePath = Join-Path $projectRoot 'dist\keywall-win-x64\keywall.exe'
$vaultPath = Join-Path $demoRoot 'demo-vault.json'
# Public disposable fixtures only. Never replace these constants with live credentials.
$demoPhrase = 'Keywall-Demo-Only-Phrase-2026'
$demoKey = 'DEMO_ONLY_NO_ACCESS_abcdefgh0123456789'
$script:demoSteps = [Collections.Generic.List[string]]::new()
function Step([string]$title) {
    Write-Host "`n=== $title ===" -ForegroundColor Cyan
    $script:demoSteps.Add("`n=== $title ===")
}
function Invoke-DemoKeywall([string[]]$Arguments, [string]$InputText, [int]$Expected = 0) {
    Write-Host ('> keywall ' + ($Arguments -join ' ')) -ForegroundColor DarkGray
    $start = [Diagnostics.ProcessStartInfo]::new($exePath)
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($part in @('--vault', $vaultPath, '--password-stdin') + $Arguments) { $start.ArgumentList.Add($part) }
    $process = [Diagnostics.Process]::Start($start)
    $outputTask = $process.StandardOutput.ReadToEndAsync()
    $errorTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($InputText)
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(30000)) { $process.Kill($true); throw 'Demo command timed out.' }
    $text = ($outputTask.GetAwaiter().GetResult() + $errorTask.GetAwaiter().GetResult()).Trim()
    $code = $process.ExitCode
    $process.Dispose()
    Write-Host $text
    Write-Host "Exit code: $code"
    $script:demoSteps.Add(('> keywall ' + ($Arguments -join ' ')))
    $script:demoSteps.Add($text)
    $script:demoSteps.Add("Exit code: $code")
    if ($code -ne $Expected) { throw "Expected exit code $Expected, received $code." }
    return $text
}
function Invoke-LocalGit([string]$Directory, [string[]]$Arguments) {
    & git -C $Directory @Arguments 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Local fixture Git setup failed.' }
}
Write-Host 'Keywall demonstration: disposable fixtures, isolated vault, local Git remote.' -ForegroundColor Yellow
Write-Host "Demo directory: $demoRoot"
Write-Host 'No live credential or remote network upload is involved.'
Step '1. Save a demo key in a password-encrypted vault'
Invoke-DemoKeywall -Arguments @('init') -InputText ($demoPhrase + "`n") | Out-Null
Invoke-DemoKeywall -Arguments @('add','demo/test','--note','Disposable demonstration key','--stdin') -InputText ($demoPhrase + "`n" + $demoKey + "`n") | Out-Null
Invoke-DemoKeywall -Arguments @('find','demo') -InputText ($demoPhrase + "`n") | Out-Null
if ([IO.File]::ReadAllText($vaultPath).Contains($demoKey)) { throw 'Plaintext unexpectedly appears in encrypted vault.' }
Write-Host 'Verified: the encrypted vault file does not contain the plaintext demo key.' -ForegroundColor Green
$script:demoSteps.Add('Verified: encrypted vault contains no plaintext demo key.')
Step '2. Retrieve the key inside a trusted child process; terminal output is masked'
$reader = Join-Path $demoRoot 'read-demo-key.ps1'
$expectedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($demoKey)))
$readerText = @'
$value = $env:DEMO_TOKEN
$actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($value)))
Write-Output ('Retrieved key matches fixture: ' + ($actual -eq '__HASH__'))
Write-Output ('Attempted plaintext output: ' + $value)
if ($actual -ne '__HASH__') { exit 1 }
'@.Replace('__HASH__', $expectedHash)
[IO.File]::WriteAllText($reader, $readerText, [Text.UTF8Encoding]::new($false))
$shellPath = (Get-Command pwsh).Source
$result = Invoke-DemoKeywall -Arguments @('run','--key','demo/test','--env','DEMO_TOKEN','--',$shellPath,'-NoProfile','-File',$reader) -InputText ($demoPhrase + "`n")
if (-not $result.Contains('Retrieved key matches fixture: True') -or -not $result.Contains('[REDACTED]') -or $result.Contains($demoKey)) { throw 'Retrieval/masking verification failed.' }
Step '3. Simulate a leaked key in a file and a ZIP'
$leakFile = Join-Path $demoRoot 'leaked.env'
[IO.File]::WriteAllText($leakFile, ('API_KEY=' + $demoKey), [Text.UTF8Encoding]::new($false))
Invoke-DemoKeywall -Arguments @('scan',$leakFile) -InputText ($demoPhrase + "`n") -Expected 2 | Out-Null
$archive = Join-Path $demoRoot 'leaked-release.zip'
Compress-Archive -LiteralPath $leakFile -DestinationPath $archive
Invoke-DemoKeywall -Arguments @('scan',$archive) -InputText ($demoPhrase + "`n") -Expected 2 | Out-Null
Write-Host 'The scanner reports the location and blocks; it does not delete the file or revoke the key.' -ForegroundColor Yellow
Step '4. A leaked key removed later from Git history still blocks push'
$repo = Join-Path $demoRoot 'leaky-repo'
$remote = Join-Path $demoRoot 'local-remote.git'
New-Item -ItemType Directory -Path $repo,$remote | Out-Null
Invoke-LocalGit -Directory $repo -Arguments @('init','-b','main')
Invoke-LocalGit -Directory $repo -Arguments @('config','user.name','Keywall Demo')
Invoke-LocalGit -Directory $repo -Arguments @('config','user.email','demo@example.invalid')
Invoke-LocalGit -Directory $remote -Arguments @('init','--bare')
Invoke-LocalGit -Directory $repo -Arguments @('remote','add','origin',$remote)
[IO.File]::WriteAllText((Join-Path $repo 'config.env'), ('API_KEY=' + $demoKey))
Invoke-LocalGit -Directory $repo -Arguments @('add','config.env')
Invoke-LocalGit -Directory $repo -Arguments @('commit','-m','Disposable fixture leak')
[IO.File]::WriteAllText((Join-Path $repo 'config.env'), 'No secret in current file.')
Invoke-LocalGit -Directory $repo -Arguments @('add','config.env')
Invoke-LocalGit -Directory $repo -Arguments @('commit','-m','Remove fixture from current file')
Invoke-DemoKeywall -Arguments @('push','origin','main','--repo',$repo) -InputText ($demoPhrase + "`n") -Expected 2 | Out-Null
$remoteRefs = & git -C $repo ls-remote --heads $remote
if ($LASTEXITCODE -ne 0 -or $remoteRefs) { throw 'Blocked demo push unexpectedly changed remote.' }
Write-Host 'Verified: local remote has no branch; nothing was pushed.' -ForegroundColor Green
$script:demoSteps.Add('Verified: local remote has no branch; nothing was pushed.')
Step '5. A clean file passes'
$cleanFile = Join-Path $demoRoot 'clean.txt'
[IO.File]::WriteAllText($cleanFile, 'This file contains no demo credential.')
Invoke-DemoKeywall -Arguments @('scan',$cleanFile) -InputText ($demoPhrase + "`n") | Out-Null
$report = Join-Path $demoRoot 'demo-results.txt'
[IO.File]::WriteAllLines($report, $script:demoSteps, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $projectRoot 'demo\latest.json'), (@{ directory=$demoRoot; vault=$vaultPath; report=$report; masterPhrase=$demoPhrase; keyAlias='demo/test' } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
Write-Host "`nAll demo checks passed. Report: $report" -ForegroundColor Green
Write-Host "Demo master phrase (public fixture only): $demoPhrase"
if ($InteractiveReveal) {
    Write-Host 'Now showing interactive reveal. Enter the demo master phrase, then REVEAL.' -ForegroundColor Cyan
    & $exePath --vault $vaultPath reveal demo/test
    if ($LASTEXITCODE -ne 0) { throw 'Interactive reveal failed.' }
    [IO.File]::AppendAllText($report, "`n=== 6. Interactive reveal ===`n> keywall reveal demo/test`nConfirmed in an interactive terminal; exit code 0.`nExtracted disposable key: $demoKey`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $projectRoot 'demo\latest.json'), (@{ directory=$demoRoot; vault=$vaultPath; report=$report; masterPhrase=$demoPhrase; keyAlias='demo/test'; interactiveReveal=$true } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
}
