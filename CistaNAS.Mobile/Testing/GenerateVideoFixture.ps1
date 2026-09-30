# Generate test media through stdout; only authenticated ciphertext is written.
param([string]$Ffmpeg = 'ffmpeg')
$ErrorActionPreference = 'Stop'
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = $Ffmpeg
$process.StartInfo.Arguments = '-v error -f lavfi -i testsrc=size=64x64:rate=10 -t 2 -c:v libx264 -pix_fmt yuv420p -g 5 -movflags frag_keyframe -f mp4 pipe:1'
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.Start() | Out-Null
$memory = New-Object System.IO.MemoryStream
$process.StandardOutput.BaseStream.CopyTo($memory)
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw 'ffmpeg failed' }
$plain = $memory.ToArray()
$nonce = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
$cipher = [byte[]]::new($plain.Length)
$tag = [byte[]]::new(16)
$aes = [System.Security.Cryptography.AesGcm]::new([byte[]]::new(32), 16)
try { $aes.Encrypt($nonce, $plain, $cipher, $tag) }
finally { [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($plain); $aes.Dispose(); $memory.Dispose(); $process.Dispose() }
$target = Join-Path $PSScriptRoot '../../CistaNAS.Tests/TestResults/viewer-video.enc'
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target)) | Out-Null
[System.IO.File]::WriteAllBytes($target, [byte[]]($nonce + $tag + $cipher))
Write-Output "Encrypted video fixture: $target"
