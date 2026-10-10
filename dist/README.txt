Windows Hardening Audit - portable audit tool (read-only)
==========================================================

START
-----
Either  Start.bat  (checks prerequisites first) or directly
start WinHardeningAudit.App.exe via double-click.

PREREQUISITES (one-time, if not already installed)
--------------------------------------------------
1. .NET 10 Desktop Runtime (x64)
   Check:  dotnet --list-runtimes   (line Microsoft.WindowsDesktop.App 10.x)
   Download: https://dotnet.microsoft.com/download/dotnet/10.0
2. Windows App Runtime 2.5 (Windows App SDK)
   Check:  Settings > Apps > Installed apps > "Windows App Runtime" 2.5.x
   Download: https://learn.microsoft.com/windows/apps/windows-app-sdk/downloads

NOTES
-----
- The tool changes nothing on the system, it only reads (registry, Defender status,
  firewall, audit policies and similar).
- Without admin rights, some checks report as "Manual review".
  The yellow banner at the top can restart the app with admin rights.
- Reports go to  Documents\HardeningAudit  (HTML/JSON/CSV).
- The check logic lives in Rules\*.json (plus Rules\l10n\en.json for English
  rule texts) and can be updated without reinstalling
  (just replace the files, note the version in About/Settings).
- Tested for Windows 11 (24H2 and newer), 64-bit.
- UI language: English and German, defaults to the system language;
  can be changed on the Settings page (takes effect after restart).

Version & rule set: see Version.txt
