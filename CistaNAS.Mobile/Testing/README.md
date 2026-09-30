Native adapters require an Android device or emulator (API 26+ for PDF).
Ordinary APKs exclude the smoke Activity and its encrypted fixture. Release builds reject the test switch.
Smoke APKs and intermediate packages use separate `bin/Debug/smoke` and `obj/Debug/smoke`
directories so switching the test flag cannot leave fixture assets in the ordinary incremental APK.
Run `./CistaNAS.Mobile/Testing/TestPackageIsolation.ps1` to build an ordinary APK, a smoke APK,
and then an incremental ordinary APK, checking the actual ZIP asset entries and Activity manifests.

From the repository root with PowerShell 7, .NET Android and ffmpeg installed:

```powershell
./CistaNAS.Mobile/Testing/GenerateVideoFixture.ps1
dotnet build CistaNAS.Mobile -p:RuntimeIdentifier=android-x64 -p:EmbedAssembliesIntoApk=true -p:EnableAndroidSmokeTests=true
adb install -r CistaNAS.Mobile/bin/Debug/smoke/net10.0-android/android-x64/com.cistanas.mobile-Signed.apk
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
It also starts the production viewer, fails an encrypted audio read after preparation,
checks that failed playback disables controls, exercises PDF page-button ordering,
and closes the PDF viewer while holding its render lock to verify the UI does not wait.
The render-lock simulation uses reflection only in this opt-in Debug test Activity.

After testing, build without EnableAndroidSmokeTests and reinstall the ordinary APK from
`bin/Debug/net10.0-android/android-x64`. When upgrading from a version that did not isolate smoke
outputs, use `-t:Rebuild` once to discard the old incremental package. Verify that
the smoke Activity is absent, and start the resolved launcher Activity three times in succession.
It should stay alive as one MainActivity instance (the Avalonia single-view root cannot be attached
to multiple Activities). Also check returning from the private viewer to the main screen.
