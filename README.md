# Windows Hardening Audit

Read-only hardening audit tool for Windows 11. It checks the local machine against
MS Security Baseline (Win11 25H2), CIS Benchmarks, and DISA STIG mappings — without
changing anything on the system. Results can be filtered, reviewed, and exported as
HTML, JSON, or CSV.

- UI: WinUI 3 desktop app (`src/WinHardeningAudit.App`)
- Engine: rule loader, check providers, scoring, exporters (`src/WinHardeningAudit.Core`)
- Rules: 536 checks in 18 JSON files (`src/WinHardeningAudit.Core/Rules/`)
- Tests: MSTest suite for providers, rule validation, export, and localization

## How it works

1. Rules are loaded from `Rules/*.json` (embedded next to the binaries, replaceable without reinstall).
2. `CheckRunner` evaluates each rule in parallel (default max 8) via a check provider:
   - `registry`: reads `HKLM\...` / `HKCU\...` values and compares with the expected value.
   - `script`: runs a PowerShell snippet, compares its first output line. Output `N/A` maps to `NotApplicable`.
   - `secedit`: parses a `secedit.exe /export` snapshot (`System Access`, `Privilege Rights`), with a `net accounts` fallback for password-policy values when running without admin rights.
   - `manual`: always requires human review (judgment calls).
3. Results are scored (`passed / (passed + failed)`), grouped by category, and can be filtered by profile and target in the UI.
4. Reports are written to `Documents\HardeningAudit` as HTML/JSON/CSV.

Statuses: `Passed`, `Failed`, `Manual`, `NotApplicable`, `Warning`, `Error`.
Severities: `Critical`, `High`, `Medium`, `Low`, `Info`.
Operators: `Equals`, `NotEquals`, `Contains`, `ContainsAll`, `GreaterOrEqual`, `LessOrEqual`.

Missing registry/secedit values honor `missingIs`: `Failed` (default), `Manual`, or `Passed` (secure default).

## Categories and profiles

Categories (11):

- Accounts & UAC
- Defender & malware protection
- BitLocker & encryption
- Firewall & network
- Secure Boot & virtualization
- Updates & maintenance
- Audit & logging
- System hardening
- Browser & Edge
- User rights
- Services

Profiles (UI labels):

- CIS Level 1 (`L1`)
- CIS Level 1+2 preview (`L1` + `L2`)
- MS Security Baseline 25H2 (`MS`)
- All profiles

Targets:

- Standalone
- Both
- Enterprise

Rule sources: `MS Baseline`, `CIS`, `STIG`, and generated `MS-W11-25H2` sets.
Each rule carries `id`, `title`, `description`, `category`, `severity`, `profil`, `ziel`,
`kapitel`, `giltAb`, `fixHint`, and an optional `notiz26H2`.

## Requirements

Target systems (audit + portable package):

- Windows 11 (24H2 or newer), 64-bit
- .NET 10 Desktop Runtime (x64) — check with `dotnet --list-runtimes` (`Microsoft.WindowsDesktop.App 10.x`)
- Windows App Runtime 2.5 (Windows App SDK) — check under Settings > Apps > Installed apps

Build machine:

- .NET 10 SDK
- Windows 10.0.26100+ SDK / WinUI workload (Windows App SDK 2.5)

## Quick start (portable package)

1. Unzip the release package.
2. Run `Start.bat` (preflight-checks .NET + App Runtime) or start `WinHardeningAudit.App.exe` directly.
3. Optional: use the yellow banner in the app to relaunch elevated. Without admin rights, some checks report `Manual: Admin/Environment`.
4. Run a scan, filter by profile/target, open Dashboard / Category / Export pages.
5. Reports land in `Documents\HardeningAudit` (`HardeningAudit-*.html/json/csv`, plus `HardeningAudit-VOLL-*.html` for the full unfiltered report).

The tool is read-only: registry, Defender status, firewall, audit policy, etc. are only read, never modified.

## Build, test, package

From the repo root:

```powershell
dotnet build WinHardeningAudit.slnx -c Release
dotnet test WinHardeningAudit.slnx -c Release
powershell -ExecutionPolicy Bypass -File dist\Build-Package.ps1
```

- `dotnet test` runs provider comparison tests, secedit parsing, rule validation (unique IDs, known categories/providers/operators), exporter checks, and localization checks (XAML `x:Uid` + code keys vs `Strings/en-US/Resources.resw`, no orphan keys).
- `dist\Build-Package.ps1` publishes `win-x64` (framework-dependent, `SelfContained=false`), copies `Rules/*.json` (plus `Rules/l10n/en.json`), `README.txt`, and `Start.bat` into `dist/out/WinHardeningAudit-<version>-win-x64`, writes `Version.txt` (date, rule count, baseline references), and zips it. `dist/out/` is git-ignored build output. The version defaults to `<Version>` from the App csproj (currently 1.0.0); override with `-Version 1.1.0`.

Publish profiles live in `src/WinHardeningAudit.App/Properties/PublishProfiles/` (`win-x64`, `win-x86`, `win-arm64`) and are versioned on purpose — the packaging script depends on `win-x64.pubxml`.

## Releases

- End users download the portable ZIP from **GitHub Releases** (no install; needs .NET 10 Desktop Runtime + Windows App Runtime 2.5, see `dist/README.txt` in the package).
- New release: bump `<Version>` in `src/WinHardeningAudit.App/WinHardeningAudit.App.csproj` (and `Identity Version` in `Package.appxmanifest`), commit, tag `v<version>` (e.g. `v1.0.0`), push including the tag. CI builds the package and attaches `WinHardeningAudit-<version>-win-x64.zip` plus `Version.txt` to the GitHub Release automatically.

## Repository layout

```text
WinHardeningAudit.slnx
src/
  WinHardeningAudit.App/        # WinUI 3 app (Pages: Dashboard, Category, Export, About, Settings)
    Assets/                     # Icons / splash / tiles
    Pages/                      # XAML + code-behind
    Services/                   # ScanService (filtering, scoring, export), Strings (L.Get/L.F)
    Strings/en-US/Resources.resw, Strings/de-DE/Resources.resw
                                # UI strings (147 keys each, EN + DE)
    Properties/PublishProfiles/ # win-x64 / x86 / arm64 (checked in)
    app.manifest, Package.appxmanifest
  WinHardeningAudit.Core/       # Engine + rules
    CheckRunner.cs              # Parallel runner, rule loading, ValidateRules
    Providers.cs                # RegistryProvider, ScriptProvider, SeceditProvider, ManualProvider
    ReportExporter.cs           # ToHtml / ToJson / ToCsv
    Models.cs                   # RuleDefinition, CheckSpec, CheckResult, ScanReport
    Rules/*.json                # 18 files, 536 rules
tests/
  WinHardeningAudit.Core.Tests/ # MSTest (Test1.cs), links Rules/*.json for validation
dist/
  Build-Package.ps1             # Portable zip builder
  Start.bat                     # Prerequisite check + launcher
  README.txt                    # English end-user notes shipped in the package
  out/                          # Generated package (ignored, not committed)
```

## Rule format

```json
[
  {
    "id": "ACCT-01",
    "title": "...",
    "description": "...",
    "category": "accounts-uac",
    "source": "MS Baseline",
    "sourceId": "UAC: EnableLUA",
    "severity": 3,
    "check": {
      "provider": "registry",
      "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      "valueName": "EnableLUA",
      "operator": "Equals",
      "expected": "1"
    },
    "fixHint": "...",
    "kapitel": "2.3 Security Options",
    "profil": "L1",
    "ziel": "both",
    "giltAb": "24H2"
  }
]
```

Notes:

- `severity`: 4 = Critical, 3 = High, 2 = Medium, 1 = Low, 0 = Info.
- `category` must be one of the 11 language-neutral keys (`accounts-uac`, `defender-malware`, `bitlocker-encryption`, `firewall-network`, `secureboot-vbs`, `updates-maintenance`, `audit-logging`, `system-hardening`, `browser-edge`, `user-rights`, `services`; see `CheckRunner.ValidCategories`).
- `profil`: `L1`, `L2`, or `MS`. `ziel`: `both`, `standalone`, or `enterprise`.
- `secedit` rules use `key`: `SystemAccess` or `PrivilegeRights`.
- Rule content texts are fully bilingual (German rule files + English `Rules/l10n/en.json` overlay covering all 536 IDs); technical references (GPO paths, registry keys, `auditpol`/`secpol` commands) stay in their source language.

Validation (`CheckRunner.ValidateRules`) rejects duplicate IDs, unknown categories/providers/operators, and missing provider fields. Keep IDs stable — exports and docs reference them.

## Localization

- UI languages: English (`en-US`) and German (`de-DE`), 147 resource keys each with enforced key parity (see tests).
- Default is the **system language** (Windows ResourceLoader); a manual override (System / English / German) lives on the About page and is persisted in `%APPDATA%\WinHardeningAudit\settings.json` (file-based, since the portable package runs unpackaged). Changing it takes effect after restart (Restart button on the About page).
- Categories, targets, profiles, sort orders, and provider `ManualKind` values are language-neutral keys (`accounts-uac`, `both`, `l1`, `severity`, `discretion`, …); display names always come from resources. Engine messages default to English and switch to German via the app overlay when the UI language is German.
- Rule content texts (titles, descriptions, recommendations, 26H2 notes) ship in German in the rule files; English is merged at load time from the sidecar overlay `Rules/l10n/en.json` (536/536 IDs covered, German fallback for missing entries). `LoadRulesFromDirectory` skips the `l10n/` folder when scanning for rules.
- Tests fail on missing `x:Uid` resources, missing code keys, orphan resource keys (either language), or key mismatch between `en-US` and `de-DE`.

## Security and limitations

- Read-only by design, but `script`-provider rules execute bundled PowerShell snippets via `powershell.exe -ExecutionPolicy Bypass`. Review `Rules/*.json` before running on sensitive systems.
- `secedit.exe`, `net.exe`, and registry reads require no install, but full fidelity needs admin rights; otherwise affected checks degrade to `Manual`.
- `N/A` script output (e.g. no TPM, no Secure Boot in a VM, non-Enterprise edition) maps to `NotApplicable`, not to pass/fail.

## License

MIT — see [LICENSE](LICENSE).
