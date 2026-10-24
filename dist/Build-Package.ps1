<# Build-Package.ps1 - builds the portable ZIP (win-x64, framework-dependent).
   Run from repo root:  powershell -ExecutionPolicy Bypass -File dist\Build-Package.ps1 [-Version 1.1.0]
   Without -Version, the version is read from src\WinHardeningAudit.App\WinHardeningAudit.App.csproj (<Version>).
#>
param([string]$Version = "")

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root 'src\WinHardeningAudit.App\WinHardeningAudit.App.csproj'
$pub = Join-Path $root 'src\WinHardeningAudit.App\bin\Release\net10.0-windows10.0.26100.0\win-x64\publish'
$dist = Join-Path $root 'dist\out'

if ([string]::IsNullOrWhiteSpace($Version)) {
  [xml]$csproj = Get-Content -LiteralPath $app -Raw
  $Version = @($csproj.Project.PropertyGroup.Version | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })[0]
  if ([string]::IsNullOrWhiteSpace($Version)) { throw 'No <Version> found in App csproj and no -Version given' }
}
Write-Output "== version $Version =="

Write-Output '== publish =='
dotnet publish $app -c Release -p:PublishProfile=win-x64.pubxml
if ($LASTEXITCODE -ne 0) { throw 'publish failed' }

$stamp = Get-Date -Format 'yyyyMMdd'
$pkgdir = Join-Path $dist "WinHardeningAudit-$Version-win-x64"
if (Test-Path -LiteralPath $pkgdir) { Remove-Item -LiteralPath $pkgdir -Recurse -Force }
New-Item -ItemType Directory -Path $pkgdir | Out-Null

Copy-Item -Path (Join-Path $pub '*') -Destination $pkgdir -Recurse -Exclude *.pdb
Copy-Item -LiteralPath (Join-Path $root 'dist\README.txt') -Destination $pkgdir
Copy-Item -LiteralPath (Join-Path $root 'dist\Start.bat') -Destination $pkgdir

$rules = Get-ChildItem -LiteralPath (Join-Path $pkgdir 'Rules') -Filter *.json -Recurse | Where-Object { $_.DirectoryName -notmatch '[\\/]l10n$' }
$n = 0
foreach ($f in $rules) { $n += (Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).Count }
$ver = "Windows Hardening Audit $Version ($stamp)`r`nRules: $n in $($rules.Count) files`r`nBased on: MS Security Baseline Win11 v25H2 + CIS Benchmark v5.0.0 + DISA STIG V2R9`r`nPrerequisites: .NET 10 Desktop Runtime (x64), Windows App Runtime 2.5`r`n"
Set-Content -LiteralPath (Join-Path $pkgdir 'Version.txt') -Value $ver -Encoding UTF8
Write-Output $ver

$zip = Join-Path $dist "WinHardeningAudit-$Version-win-x64.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $pkgdir '*') -DestinationPath $zip
$mb = [math]::Round((Get-Item -LiteralPath $zip).Length / 1MB, 1)
$mbUnpacked = [math]::Round(((Get-ChildItem -LiteralPath $pkgdir -Recurse -File | Measure-Object Length -Sum).Sum) / 1MB, 1)
Write-Output "ZIP: $zip ($mb MB, entpackt $mbUnpacked MB)"
