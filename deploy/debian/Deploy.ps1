[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$HostName,
    [string]$UserName = "deploy",
    [string]$SettingsFile = (Join-Path $PSScriptRoot "appsettings.json"),
    [string]$SshKeyPath,
    [string]$SshPrivateKey,
    [string]$SshCertificate,
    [string]$RemoteRoot = "/opt/cistanas",
    [ValidateSet("linux-x64", "linux-arm64")]
    [string]$RuntimeIdentifier = "linux-x64",
    [string]$GitHubRepository = "actbit/CistaNAS",
    [string]$SshAllowFrom,
    [string]$OriginCertificateFile,
    [string]$OriginKeyFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Native {
    param([Parameter(Mandatory = $true)] [string]$FilePath, [Parameter(Mandatory = $true)] [string[]]$Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "コマンドに失敗しました: $FilePath (exit code $LASTEXITCODE)" }
}
function Test-Command {
    param([Parameter(Mandatory = $true)] [string]$Name)
    if ($null -eq (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "必要なコマンドが見つかりません: $Name" }
}
function Assert-SafeValue {
    param([Parameter(Mandatory = $true)] [string]$Value, [Parameter(Mandatory = $true)] [string]$Name, [Parameter(Mandatory = $true)] [string]$Pattern)
    if ($Value -notmatch $Pattern) { throw "$Name に使用できない文字が含まれています。" }
}
function Write-Utf8SecretFile {
    param([Parameter(Mandatory = $true)] [string]$Path, [Parameter(Mandatory = $true)] [string]$Value)
    $normalizedValue = $Value -replace "`r`n", "`n" -replace "`r", "`n"
    if (-not $normalizedValue.EndsWith("`n")) { $normalizedValue += "`n" }
    [IO.File]::WriteAllText($Path, $normalizedValue, [Text.UTF8Encoding]::new($false))
}

Test-Command "dotnet"
Test-Command "ssh"
Test-Command "scp"
Test-Command "tar"
if (-not (Test-Path -LiteralPath $SettingsFile -PathType Leaf)) { throw "秘密設定ファイルが見つかりません: $SettingsFile`nappsettings.json.exampleをコピーして作成してください。" }
$SettingsFile = (Resolve-Path -LiteralPath $SettingsFile).Path

if (-not [string]::IsNullOrWhiteSpace($OriginCertificateFile) -or -not [string]::IsNullOrWhiteSpace($OriginKeyFile)) {
    if ([string]::IsNullOrWhiteSpace($OriginCertificateFile) -or [string]::IsNullOrWhiteSpace($OriginKeyFile) -or
        -not (Test-Path -LiteralPath $OriginCertificateFile -PathType Leaf) -or -not (Test-Path -LiteralPath $OriginKeyFile -PathType Leaf)) {
        throw "Origin証明書と秘密鍵は両方とも存在するファイルを指定してください。"
    }
    $OriginCertificateFile = (Resolve-Path -LiteralPath $OriginCertificateFile).Path
    $OriginKeyFile = (Resolve-Path -LiteralPath $OriginKeyFile).Path
}

Assert-SafeValue $HostName "HostName" "^[A-Za-z0-9][A-Za-z0-9.-]*$"
Assert-SafeValue $UserName "UserName" "^[A-Za-z0-9._-]+$"
Assert-SafeValue $RemoteRoot "RemoteRoot" "^/[A-Za-z0-9._/-]+$"
Assert-SafeValue $GitHubRepository "GitHubRepository" "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
if (-not [string]::IsNullOrWhiteSpace($SshKeyPath) -and -not [string]::IsNullOrWhiteSpace($SshPrivateKey)) {
    throw "SshKeyPath と SshPrivateKey は同時に指定できません。"
}
if (-not [string]::IsNullOrWhiteSpace($SshCertificate) -and
    [string]::IsNullOrWhiteSpace($SshKeyPath) -and
    [string]::IsNullOrWhiteSpace($SshPrivateKey)) {
    throw "SshCertificate を使う場合は、SshKeyPath、SshPrivateKey、またはSSHエージェントを指定してください。"
}
if ($SshAllowFrom -and ($SshAllowFrom.Contains("'") -or $SshAllowFrom.Contains('"') -or $SshAllowFrom.Contains(';') -or $SshAllowFrom.Contains('`') -or $SshAllowFrom -notmatch "^[0-9A-Fa-f:./\s]+$")) {
    throw "SshAllowFrom にシェル特殊文字は指定できません。"
}

try {
    $settings = Get-Content -LiteralPath $SettingsFile -Raw | ConvertFrom-Json
    $signingKey = [string]$settings.CistaNas.Jwt.SigningKey
    $adminPassword = [string]$settings.CistaNas.Auth.DefaultAdminPassword
    if ($signingKey -like "REPLACE_WITH_*") { throw "CistaNas.Jwt.SigningKey はサンプル値から変更してください。" }
    if ([Text.Encoding]::UTF8.GetByteCount($signingKey) -lt 32) { throw "CistaNas.Jwt.SigningKey はUTF-8で32バイト以上にしてください。" }
    if ([string]::IsNullOrWhiteSpace($adminPassword) -or $adminPassword -like "REPLACE_WITH_*") { throw "CistaNas.Auth.DefaultAdminPassword を設定してください。" }
}
catch { throw "appsettings.json の検査に失敗しました: $($_.Exception.Message)" }

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$projectFile = Join-Path $repositoryRoot "CistaNAS.Web\CistaNAS.Web.csproj"
$deployId = [Guid]::NewGuid().ToString("N")
$version = "manual-$deployId"
$publishDirectory = Join-Path ([IO.Path]::GetTempPath()) "cistanas-publish-$deployId"
$localPackage = Join-Path ([IO.Path]::GetTempPath()) "cistanas-$deployId.tar.gz"
$target = "$UserName@$HostName"
$sshArguments = @()
$scpArguments = @()
$sshCredentialDirectory = $null
$sshPrivateKeyFile = $null
$sshCertificateFile = $null
if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) {
    if (-not (Test-Path -LiteralPath $SshKeyPath -PathType Leaf)) { throw "SSH秘密鍵が見つかりません: $SshKeyPath" }
    $sshArguments += @("-i", $SshKeyPath)
    $scpArguments += @("-i", $SshKeyPath)
}
if (-not [string]::IsNullOrWhiteSpace($SshPrivateKey) -or -not [string]::IsNullOrWhiteSpace($SshCertificate)) {
    $sshCredentialDirectory = Join-Path ([IO.Path]::GetTempPath()) "cistanas-ssh-$deployId"
    New-Item -ItemType Directory -Path $sshCredentialDirectory -Force | Out-Null
}
if (-not [string]::IsNullOrWhiteSpace($SshPrivateKey)) {
    $sshPrivateKeyFile = Join-Path $sshCredentialDirectory "id_ssh"
    Write-Utf8SecretFile -Path $sshPrivateKeyFile -Value $SshPrivateKey
    $sshArguments += @("-i", $sshPrivateKeyFile)
    $scpArguments += @("-i", $sshPrivateKeyFile)
}
if (-not [string]::IsNullOrWhiteSpace($SshCertificate)) {
    $sshCertificateFile = Join-Path $sshCredentialDirectory "id_ssh-cert.pub"
    Write-Utf8SecretFile -Path $sshCertificateFile -Value $SshCertificate
    $certificateArgument = "CertificateFile=$sshCertificateFile"
    $sshArguments += @("-o", $certificateArgument)
    $scpArguments += @("-o", $certificateArgument)
}

$remoteBootstrap = "/tmp/cistanas-bootstrap-$deployId.sh"
$remoteService = "/tmp/cistanas-service-$deployId.service"
$remoteUpdater = "/tmp/cistanas-update-$deployId.sh"
$remoteUpdateService = "/tmp/cistanas-update-$deployId.service"
$remoteUpdateCheckService = "/tmp/cistanas-update-check-$deployId.service"
$remoteUpdateCheckPath = "/tmp/cistanas-update-check-$deployId.path"
$remoteUpdateApplyPath = "/tmp/cistanas-update-apply-$deployId.path"
$remotePackage = "/tmp/cistanas-package-$deployId.tar.gz"
$remoteSettings = "/tmp/cistanas-settings-$deployId.json"
$remoteCert = "/tmp/cistanas-origin-$deployId.crt"
$remoteKey = "/tmp/cistanas-origin-$deployId.key"

try {
    Write-Host "Debian向けの自己完結.NET配布物をビルドしています..."
    if (Test-Path -LiteralPath $publishDirectory) { Remove-Item -LiteralPath $publishDirectory -Recurse -Force }
    Invoke-Native "dotnet" @("publish", $projectFile, "--configuration", "Release", "--runtime", $RuntimeIdentifier, "--self-contained", "true", "--output", $publishDirectory, "-p:DebugType=None", "-p:DebugSymbols=false")
    Invoke-Native "tar" @("-czf", $localPackage, "-C", $publishDirectory, ".")

    $bootstrapPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "bootstrap.sh")).Path
    $servicePath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "cistanas.service")).Path
    $updaterPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "cistanas-update.sh")).Path
    $updateServicePath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "cistanas-update.service")).Path
    $updateCheckServicePath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "cistanas-update-check.service")).Path
    $updateCheckPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "cistanas-update-check.path")).Path
    $updateApplyPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "cistanas-update-apply.path")).Path
    Invoke-Native "scp" ($scpArguments + @($bootstrapPath, "$target`:$remoteBootstrap"))
    Invoke-Native "scp" ($scpArguments + @($servicePath, "$target`:$remoteService"))
    Invoke-Native "scp" ($scpArguments + @($updaterPath, "$target`:$remoteUpdater"))
    Invoke-Native "scp" ($scpArguments + @($updateServicePath, "$target`:$remoteUpdateService"))
    Invoke-Native "scp" ($scpArguments + @($updateCheckServicePath, "$target`:$remoteUpdateCheckService"))
    Invoke-Native "scp" ($scpArguments + @($updateCheckPath, "$target`:$remoteUpdateCheckPath"))
    Invoke-Native "scp" ($scpArguments + @($updateApplyPath, "$target`:$remoteUpdateApplyPath"))

    $sshAllowArgument = if ($null -eq $SshAllowFrom) { "" } else { $SshAllowFrom }
    $originCertArgument = if ([string]::IsNullOrWhiteSpace($OriginCertificateFile)) { "" } else { $remoteCert }
    $originKeyArgument = if ([string]::IsNullOrWhiteSpace($OriginKeyFile)) { "" } else { $remoteKey }
    if ($originCertArgument) {
        Invoke-Native "scp" ($scpArguments + @($OriginCertificateFile, "$target`:$remoteCert"))
        Invoke-Native "scp" ($scpArguments + @($OriginKeyFile, "$target`:$remoteKey"))
    }
    $sudoPrefix = if ([string]::IsNullOrWhiteSpace($SshAllowFrom)) { "sudo --preserve-env=SSH_CONNECTION" } else { "sudo" }
    $bootstrapCommand = "$sudoPrefix bash '$remoteBootstrap' '$RemoteRoot' '$UserName' '$sshAllowArgument' '$originCertArgument' '$originKeyArgument' '$GitHubRepository' '$remoteService' '$remoteUpdater' '$remoteUpdateService' '$remoteUpdateCheckService' '$remoteUpdateCheckPath' '$remoteUpdateApplyPath'"
    Invoke-Native "ssh" ($sshArguments + @($target, $bootstrapCommand))

    Write-Host "配布物と本番設定を転送しています..."
    Invoke-Native "scp" ($scpArguments + @($localPackage, "$target`:$remotePackage"))
    Invoke-Native "scp" ($scpArguments + @($SettingsFile, "$target`:$remoteSettings"))

    $remoteInstallCommand = @"
set -eu
sudo install -d -o root -g root -m 0755 '$RemoteRoot/releases/$version'
sudo tar -xzf '$remotePackage' -C '$RemoteRoot/releases/$version'
sudo chown -R root:root '$RemoteRoot/releases/$version'
sudo chmod 0755 '$RemoteRoot/releases/$version/CistaNAS.Web'
sudo ln -sfnT '$RemoteRoot/releases/$version' '$RemoteRoot/current'
sudo install -o root -g cistanas -m 0640 '$remoteSettings' /etc/cistanas/appsettings.Production.json
sudo systemctl daemon-reload
sudo systemctl restart cistanas.service
if ! curl --fail --silent --show-error --retry 30 --retry-delay 1 --retry-connrefused http://127.0.0.1:8080/health >/dev/null; then
    sudo systemctl --no-pager --full status cistanas.service || true
    exit 1
fi
"@
    Invoke-Native "ssh" ($sshArguments + @($target, $remoteInstallCommand.Trim()))
    Write-Host "systemdデプロイが完了しました: $version ($RuntimeIdentifier)"
}
finally {
    if (Test-Path -LiteralPath $publishDirectory) { Remove-Item -LiteralPath $publishDirectory -Recurse -Force }
    if (Test-Path -LiteralPath $localPackage) { Remove-Item -LiteralPath $localPackage -Force }
    try {
        Invoke-Native "ssh" ($sshArguments + @($target, "rm -f '$remoteBootstrap' '$remoteService' '$remoteUpdater' '$remoteUpdateService' '$remoteUpdateCheckService' '$remoteUpdateCheckPath' '$remoteUpdateApplyPath' '$remotePackage' '$remoteSettings' '$remoteCert' '$remoteKey'"))
    }
    catch { Write-Warning "一時ファイルの自動削除に失敗しました。Debian側の /tmp/cistanas-* を確認してください。" }
    if ($null -ne $sshCredentialDirectory -and (Test-Path -LiteralPath $sshCredentialDirectory)) {
        Remove-Item -LiteralPath $sshCredentialDirectory -Recurse -Force
    }
}
