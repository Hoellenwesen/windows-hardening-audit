<# New-Release.ps1 - prepares a release locally (semi-automatic).
   Bumps the version, self-tests (build + tests), then commits and tags.
   Pushing stays manual:  git push  +  git push origin <tag>  (triggers the CI release).

   Run from repo root:
     powershell -ExecutionPolicy Bypass -File dist\New-Release.ps1 -Version 1.1.0
     powershell -ExecutionPolicy Bypass -File dist\New-Release.ps1 -Version 1.1.0 -WhatIf   # dry run
     powershell -ExecutionPolicy Bypass -File dist\New-Release.ps1 -Version 1.1.0 -Force     # no confirmation prompt
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$Version = "",
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csproj = Join-Path $root 'src\WinHardeningAudit.App\WinHardeningAudit.App.csproj'
$manifest = Join-Path $root 'src\WinHardeningAudit.App\Package.appxmanifest'
$readme = Join-Path $root 'README.md'

function Read-TextPreservingBom([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
  $enc = if ($hasBom) { [System.Text.Encoding]::UTF8 } else { New-Object System.Text.UTF8Encoding $false }
  return @{ Text = $enc.GetString($bytes); Encoding = $enc }
}

function Write-TextPreservingBom([string]$path, [string]$text) {
  $current = Read-TextPreservingBom $path
  [System.IO.File]::WriteAllText($path, $text, $current.Encoding)
}

if ([string]::IsNullOrWhiteSpace($Version)) {
  $Version = Read-Host 'Version (x.y.z, e.g. 1.1.0)'
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version '$Version' is not x.y.z" }
$tag = "v$Version"

# 1. Guards: clean tree, tag must not exist yet.
$dirty = git -C $root status --porcelain
if ($dirty) { throw "Working tree not clean - commit or stash first:`n$dirty" }
if (git -C $root tag --list $tag) { throw "Tag $tag already exists" }

[xml]$xml = Get-Content -LiteralPath $csproj -Raw
$current = @($xml.Project.PropertyGroup.Version | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })[0]
Write-Output "Version bump: $current -> $Version (tag $tag)"

if (-not $Force -and -not $WhatIfPreference) {
  $ok = Read-Host "Bump + build/test + commit + tag '$tag' ausfuehren? (j/N)"
  if ($ok -ne 'j') { Write-Output 'Abgebrochen.'; return }
}

if ($PSCmdlet.ShouldProcess("Version $Version", "Bump version in csproj/manifest/README")) {
  # 2a. csproj <Version> (single source of truth for Build-Package.ps1).
  # NOTE: ${1}/${2} syntax - plain $1 would merge with a following digit into $19 etc.
  $t = (Read-TextPreservingBom $csproj).Text
  $t2 = [regex]::Replace($t, '(<Version>)\d+\.\d+\.\d+(</Version>)', "`${1}$Version`${2}")
  if ($t2 -eq $t) { throw 'No <Version>x.y.z</Version> found in App csproj' }
  Write-TextPreservingBom $csproj $t2

  # 2b. Manifest Identity Version (4-part). Anchored with whitespace so
  # MinVersion/MaxVersionTested stay untouched.
  $t = (Read-TextPreservingBom $manifest).Text
  $t2 = [regex]::Replace($t, '\sVersion="\d+\.\d+\.\d+\.\d+"', " Version=`"$Version.0`"")
  if ($t2 -eq $t) { throw 'No Identity Version found in Package.appxmanifest' }
  Write-TextPreservingBom $manifest $t2

  # 2c. README version mentions.
  $t = (Read-TextPreservingBom $readme).Text
  $t2 = [regex]::Replace($t, '\(currently \d+\.\d+\.\d+\)', "(currently $Version)")
  $t2 = [regex]::Replace($t2, 'e\.g\. `v\d+\.\d+\.\d+`', "e.g. ``v$Version``")
  if ($t2 -eq $t) { Write-Output 'Hinweis: keine README-Versionsstellen gefunden (ok, falls Doku versionlos ist).' }
  Write-TextPreservingBom $readme $t2
}

if ($PSCmdlet.ShouldProcess("slnx", "dotnet build + test")) {
  # 3. Self-test: nothing gets committed on red.
  Write-Output '== build =='
  dotnet build (Join-Path $root 'WinHardeningAudit.slnx') -c Release --nologo
  if ($LASTEXITCODE -ne 0) { throw 'build failed - nothing committed' }
  Write-Output '== test =='
  dotnet test (Join-Path $root 'WinHardeningAudit.slnx') -c Release --no-build --nologo
  if ($LASTEXITCODE -ne 0) { throw 'tests failed - nothing committed' }
}

if ($PSCmdlet.ShouldProcess($tag, "git commit + tag (local only, no push)")) {
  # 4. Commit + tag, local only.
  git -C $root add -A
  git -C $root commit -m "chore: release $tag"
  git -C $root tag $tag
}

Write-Output ''
Write-Output 'Fertig (nur lokal). Naechste Schritte - bewusst manuell:'
Write-Output '  git push'
Write-Output "  git push origin $tag   # loest das CI-Release aus"
