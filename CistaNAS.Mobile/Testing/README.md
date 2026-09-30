Native adapters require an Android device or emulator (API 26+ for PDF).
Ordinary APKs exclude the smoke Activity and its encrypted fixture. Release builds reject the test switch.

From the repository root with PowerShell 7, .NET Android and ffmpeg installed:

```powershell
./CistaNAS.Mobile/Testing/GenerateVideoFixture.ps1
dotnet build CistaNAS.Mobile -p:RuntimeIdentifier=android-x64 -p:EmbedAssembliesIntoApk=true -p:EnableAndroidSmokeTests=true
adb install -r CistaNAS.Mobile/bin/Debug/net10.0-android/android-x64/com.cistanas.mobile-Signed.apk
adb logcat -c
adb shell am start -n com.cistanas.mobile/.StreamingSmokeActivity
adb logcat -s CistaNASSmoke
```

To exercise the actual private viewer UI, use `am start -W -S` with `--es viewer pdf`,
`--es viewer video` or `--es viewer audio` (this resets the test process between fixtures).
Check controls, closing it, and reopening the
launcher while a viewer is active. Test fixtures stay in RAM.

The smoke test synthesizes PCM audio and a two-page PDF in RAM. ffmpeg writes video through stdout;
the generator persists only AES-GCM ciphertext under ignored TestResults. These fixtures are served
as encrypted E2EE chunks to the production StreamingFileService, MediaDataSource and proxy PDF descriptor.
The test checks actual Android preparation, seek, playback completion, reverse page rendering,
read rejection after close and unchanged application cache files.

After testing, rebuild without EnableAndroidSmokeTests and reinstall the ordinary APK. Verify that
the smoke Activity is absent, and start the resolved launcher Activity three times in succession.
It should stay alive as one MainActivity instance (the Avalonia single-view root cannot be attached
to multiple Activities). Also check returning from the private viewer to the main screen.
