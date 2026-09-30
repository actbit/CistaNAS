param(
    [ValidateSet('android-x64', 'android-arm64')]
    [string]$RuntimeIdentifier = 'android-x64'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$mobileRoot = Join-Path $repoRoot 'CistaNAS.Mobile'
$project = Join-Path $mobileRoot 'CistaNAS.Mobile.csproj'
$fixture = Join-Path $repoRoot 'CistaNAS.Tests/TestResults/viewer-video.enc'
if (-not (Test-Path -LiteralPath $fixture)) {
    & (Join-Path $PSScriptRoot 'GenerateVideoFixture.ps1')
}

function Build-Package([bool]$Smoke, [bool]$Rebuild = $false) {
    $buildArguments = @('build', $project, "-p:RuntimeIdentifier=$RuntimeIdentifier", '-p:EmbedAssembliesIntoApk=true')
    if ($Smoke) { $buildArguments += '-p:EnableAndroidSmokeTests=true' }
    if ($Rebuild) { $buildArguments += '-t:Rebuild' }
    & dotnet @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'Android build failed.' }
}

function Assert-Package([bool]$Smoke) {
    $mode = if ($Smoke) { 'Debug/smoke' } else { 'Debug' }
    $relative = "$mode/net10.0-android/$RuntimeIdentifier"
    $package = Join-Path $mobileRoot "bin/$relative/com.cistanas.mobile-Signed.apk"
    $archive = [System.IO.Compression.ZipFile]::OpenRead($package)
    try {
        $hasFixture = $null -ne $archive.GetEntry('assets/viewer-video.enc')
        if ($hasFixture -ne $Smoke) { throw "Unexpected fixture inclusion: $package" }
    }
    finally { $archive.Dispose() }
    [xml]$manifest = Get-Content (Join-Path $mobileRoot "obj/$relative/android/AndroidManifest.xml") -Raw
    $ns = 'http://schemas.android.com/apk/res/android'
    $hasSmoke = @($manifest.manifest.application.activity | Where-Object {
        $_.GetAttribute('name', $ns) -eq 'com.cistanas.mobile.StreamingSmokeActivity'
    }).Count -gt 0
    if ($hasSmoke -ne $Smoke) { throw "Unexpected smoke Activity inclusion: $package" }
    $viewer = $manifest.manifest.application.activity | Where-Object {
        $_.GetAttribute('name', $ns) -eq 'com.cistanas.mobile.StreamingViewerActivity'
    }
    if ($viewer.GetAttribute('exported', $ns) -ne 'false') { throw 'Viewer must remain private.' }
}

# Discard old packages once, then specifically verify the incremental test ->
# ordinary switch that previously retained a removed fixture asset in the APK.
Build-Package -Smoke $false -Rebuild $true
Assert-Package -Smoke $false
Build-Package -Smoke $true
Assert-Package -Smoke $true
Build-Package -Smoke $false
Assert-Package -Smoke $false
Write-Output 'PASS ordinary -> smoke -> ordinary package isolation'
