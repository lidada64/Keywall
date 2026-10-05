param([string]$RuntimeVersion)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    if (-not $RuntimeVersion) {
        $metadata = Invoke-RestMethod 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/8.0/releases.json'
        $RuntimeVersion = $metadata.'latest-runtime'
    }
    if ($RuntimeVersion -notmatch '^8\.0\.\d+$') { throw 'Invalid runtime version.' }
    $outputDir = Join-Path $projectRoot 'dist/keywall-win-x64'
    dotnet publish src/Keywall/Keywall.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -p:RuntimeFrameworkVersion=$RuntimeVersion --configfile NuGet.Config -o $outputDir
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
    Copy-Item -LiteralPath (Join-Path $outputDir 'keywall.exe') -Destination (Join-Path $outputDir 'kw.exe') -Force
    Copy-Item -LiteralPath 'README.md','SECURITY.md','LICENSE' -Destination $outputDir
    # The single-file bundle embeds runtime files. Ship legal texts explicitly as well.
    $packageRoot = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.nuget/packages' }
    $runtimeRoot = Join-Path $packageRoot "microsoft.netcore.app.runtime.win-x64/$RuntimeVersion"
    foreach ($legal in @('LICENSE.TXT','THIRD-PARTY-NOTICES.TXT')) {
        $source = Join-Path $runtimeRoot $legal
        if (-not (Test-Path -LiteralPath $source)) { throw "Runtime license file missing: $legal" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $outputDir "DOTNET-$legal")
    }
    Set-Content -LiteralPath (Join-Path $outputDir 'BUILD.txt') -Value "Keywall 0.1.4`nRuntime: .NET $RuntimeVersion win-x64`nUnsigned executable; independently review before trusting it." -Encoding utf8
    $zip = Join-Path $projectRoot 'dist/keywall-0.1.4-win-x64.zip'
    # A fixed allowlist prevents stale files, test fixtures or debug symbols entering the release.
    $assets = @('keywall.exe','kw.exe','README.md','SECURITY.md','LICENSE','DOTNET-LICENSE.TXT','DOTNET-THIRD-PARTY-NOTICES.TXT','BUILD.txt') | ForEach-Object { Join-Path $outputDir $_ }
    Compress-Archive -LiteralPath $assets -DestinationPath $zip -Force
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$zip.sha256" -Value "$hash  keywall-0.1.4-win-x64.zip" -Encoding ascii
    Write-Output $zip
    Write-Output "$hash  keywall-0.1.4-win-x64.zip"
} finally { Pop-Location }
