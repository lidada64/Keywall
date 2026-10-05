param(
    [string]$SourceDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\keywall-win-x64'),
    [string]$InstallDirectory = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\Keywall')
)
$ErrorActionPreference = 'Stop'
$sourcePath = [IO.Path]::GetFullPath($SourceDirectory)
$installPath = [IO.Path]::GetFullPath($InstallDirectory)
$files = @('keywall.exe','kw.exe','README.md','SECURITY.md','LICENSE','DOTNET-LICENSE.TXT','DOTNET-THIRD-PARTY-NOTICES.TXT','BUILD.txt')
foreach ($name in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $sourcePath $name) -PathType Leaf)) { throw "Missing release file: $name" }
}
$marker = Join-Path $installPath 'keywall-install.json'
if (Test-Path -LiteralPath $installPath) {
    if ((Get-Item -LiteralPath $installPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Install directory cannot be a reparse point.' }
    if ((Get-ChildItem -LiteralPath $installPath -Force | Measure-Object).Count -gt 0 -and -not (Test-Path -LiteralPath $marker)) {
        throw 'Existing directory is not marked as a Keywall installation. Choose another directory.'
    }
} else { New-Item -ItemType Directory -Path $installPath -Force | Out-Null }
# Release updates stop only this installation's private in-memory session helpers.
# Ordinary CLI commands are not terminated, and vault contents are not accessed.
if (Test-Path -LiteralPath $marker) {
    $ownedExecutables = @((Join-Path $installPath 'keywall.exe'), (Join-Path $installPath 'kw.exe'))
    $helpers = Get-CimInstance Win32_Process -Filter "Name='keywall.exe' OR Name='kw.exe'" |
        Where-Object { $_.ExecutablePath -in $ownedExecutables -and $_.CommandLine -match '(?:^|\s)_session(?:\s|$)' }
    foreach ($helper in $helpers) { Stop-Process -Id $helper.ProcessId -ErrorAction Stop }
}
foreach ($name in $files) {
    $destination = Join-Path $installPath $name
    if (Test-Path -LiteralPath $destination) {
        if ((Get-Item -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Destination cannot be a link: $name" }
    }
    if ($sourcePath -ne $installPath) { Copy-Item -LiteralPath (Join-Path $sourcePath $name) -Destination $destination -Force }
    if ((Get-FileHash -LiteralPath (Join-Path $sourcePath $name)).Hash -ne (Get-FileHash -LiteralPath $destination).Hash) { throw "Copy verification failed: $name" }
}
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = @($userPath -split ';' | Where-Object { $_ })
$alreadyPresent = @($entries | Where-Object { $_.TrimEnd('\') -ieq $installPath.TrimEnd('\') }).Count -gt 0
if (-not $alreadyPresent) {
    $updatedPath = (@($entries) + @($installPath)) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $updatedPath, 'User')
}
if (-not ($env:Path -split ';' | Where-Object { $_.TrimEnd('\') -ieq $installPath.TrimEnd('\') })) {
    $env:Path = $env:Path.TrimEnd(';') + ';' + $installPath
}
@{ app = 'Keywall'; version = '0.1.4'; path = $installPath; installedUtc = [DateTime]::UtcNow.ToString('o'); executableSha256 = (Get-FileHash -LiteralPath (Join-Path $installPath 'keywall.exe')).Hash.ToLowerInvariant() } |
    ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding utf8
& (Join-Path $installPath 'keywall.exe') version
if ($LASTEXITCODE -ne 0) { throw 'Installed executable check failed.' }
& (Join-Path $installPath 'kw.exe') version
if ($LASTEXITCODE -ne 0) { throw 'Installed shorthand check failed.' }
Write-Output "Installed: $installPath"
Write-Output 'User PATH configured. For existing terminals, reopen the application or refresh PATH.'
$vaultPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Keywall\vault.json'
Write-Output ('Default vault exists: ' + (Test-Path -LiteralPath $vaultPath -PathType Leaf))
if (Test-Path -LiteralPath $vaultPath -PathType Leaf) { Write-Output 'Unlock privately in your own terminal: kw login' }
else { Write-Output 'Initialize privately in your own terminal: kw init' }
