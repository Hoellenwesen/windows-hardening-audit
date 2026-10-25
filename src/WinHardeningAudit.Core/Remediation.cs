using System.Diagnostics;
using System.Text;
using System.Text.Json;
using WinHardeningAudit.Core.Models;

namespace WinHardeningAudit.Core.Engine;

/// <summary>Result of a remediation ("Beheben") run.</summary>
public sealed record RemediationOutcome
{
    public bool Success { get; init; }
    /// <summary>Not executed, e.g. no auto remediation for this rule or missing admin rights.</summary>
    public bool Blocked { get; init; }
    public string Message { get; init; } = "";
    public string? BackupPath { get; init; }
    public bool RequiresReboot { get; init; }
}

public static class RemediationRunner
{
    public static string BackupDir
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "WinHardeningAudit", "fixes");

    public static bool CanAutoFix(RuleDefinition rule)
        => rule.Profil == "L1" && rule.Remediation is { Mode: "auto" } && rule.Remediation.Actions.Count > 0;

    /// <summary>Snapshot old values, write a backup, then apply all actions.</summary>
    public static async Task<RemediationOutcome> ApplyAsync(RuleDefinition rule, CancellationToken ct = default)
    {
        var rem = rule.Remediation;
        if (rem is not { Mode: "auto", Actions.Count: > 0 })
            return new RemediationOutcome { Success = false, Blocked = true, Message = "no auto remediation" };
        if (!CheckRunner.IsElevated())
            return new RemediationOutcome { Success = false, Blocked = true, Message = "admin rights required" };

        Directory.CreateDirectory(BackupDir);
        var stamp = $"{DateTime.Now:yyyyMMdd-HHmmss}";
        var entries = new List<RemediationBackupEntry>();

        // 1. secedit: full security-policy export as rollback, before anything else.
        if (rem.Actions.Any(a => a.Type == "secedit"))
        {
            var inf = Path.Combine(BackupDir, $"{stamp}-{rule.Id}.secedit.inf");
            var export = await PowerShellFile.RunAsync($"secedit /export /cfg \"{inf}\" /areas SECURITYPOLICY; if($LASTEXITCODE -ne 0){{exit 1}}", ct);
            if (!export.Ok)
                return Fail($"secedit export failed: {export.Text}", null);
            entries.Add(new RemediationBackupEntry(
                "secedit", JsonSerializer.Serialize(new { inf }),
                $"$sdb=[IO.Path]::Combine([IO.Path]::GetTempPath(),('wha-undo-' + [guid]::NewGuid().ToString('N') + '.sdb')); secedit /configure /db $sdb /cfg \"{inf}\" /areas SECURITYPOLICY /overwrite"));
        }

        // 2. snapshot every action.
        foreach (var a in rem.Actions)
        {
            var snap = await PowerShellFile.RunAsync(RemediationScript.Snapshot(a), ct);
            if (!snap.Ok)
                return Fail($"snapshot failed ({a.Type}): {snap.Text}", null);
            var undo = RemediationScript.UndoFromSnapshot(a, snap.Text);
            if (string.IsNullOrWhiteSpace(undo))
                return Fail($"snapshot unusable ({a.Type}): {snap.Text}", null);
            entries.Add(new RemediationBackupEntry(a.Type, snap.Text, undo));
        }

        // 3. write the backup before touching anything.
        var backupPath = Path.Combine(BackupDir, $"{stamp}-{rule.Id}.json");
        var backup = new RemediationBackup
        {
            RuleId = rule.Id,
            Title = rule.Title,
            Timestamp = DateTimeOffset.Now,
            Entries = entries,
        };
        await File.WriteAllTextAsync(backupPath, JsonSerializer.Serialize(backup, new JsonSerializerOptions { WriteIndented = true }), ct);

        // 4. apply.
        var log = new StringBuilder();
        foreach (var a in rem.Actions)
        {
            var result = await PowerShellFile.RunAsync(RemediationScript.Apply(a), ct);
            log.AppendLine($"[{a.Type}] {(result.Ok ? "ok" : "FAILED")}: {result.Text}");
            if (!result.Ok)
                return new RemediationOutcome
                {
                    Success = false,
                    Message = $"apply failed ({a.Type}): {result.Text}\r\nBackup: {backupPath}",
                    BackupPath = backupPath,
                    RequiresReboot = rem.RequiresReboot,
                };
        }
        return new RemediationOutcome
        {
            Success = true,
            Message = log.ToString().Trim(),
            BackupPath = backupPath,
            RequiresReboot = rem.RequiresReboot,
        };
    }

    /// <summary>Undo one fix using its backup file.</summary>
    public static async Task<RemediationOutcome> UndoAsync(string backupPath, CancellationToken ct = default)
    {
        if (!File.Exists(backupPath))
            return new RemediationOutcome { Success = false, Message = "backup not found" };
        RemediationBackup? backup;
        try
        {
            backup = JsonSerializer.Deserialize<RemediationBackup>(await File.ReadAllTextAsync(backupPath, ct));
        }
        catch (Exception ex)
        {
            return new RemediationOutcome { Success = false, Message = $"backup unreadable: {ex.Message}" };
        }
        if (backup is null)
            return new RemediationOutcome { Success = false, Message = "backup empty" };

        var log = new StringBuilder();
        foreach (var e in backup.Entries)
        {
            var result = await PowerShellFile.RunAsync(e.UndoScript, ct);
            log.AppendLine($"[{e.Type}] {(result.Ok ? "ok" : "FAILED")}: {result.Text}");
            if (!result.Ok)
                return new RemediationOutcome { Success = false, Message = $"undo failed ({e.Type}): {result.Text}\r\n{log}" };
        }
        return new RemediationOutcome { Success = true, Message = log.ToString().Trim() };
    }

    private static RemediationOutcome Fail(string message, string? backupPath)
        => new() { Success = false, Message = message, BackupPath = backupPath };
}

public sealed record RemediationBackup
{
    public string RuleId { get; init; } = "";
    public string Title { get; init; } = "";
    public DateTimeOffset Timestamp { get; init; }
    public List<RemediationBackupEntry> Entries { get; init; } = new();
}

public sealed record RemediationBackupEntry(string Type, string Snapshot, string UndoScript);

/// <summary>Generates the PowerShell commands for apply, snapshot (backup) and undo.</summary>
public static class RemediationScript
{
    // ---- apply ---------------------------------------------------------------

    public static string Apply(RemediationAction a) => a.Type switch
    {
        "registry" => RegistryApply(a),
        "service" => $"Set-Service -Name '{a.Name}' -StartupType {a.StartType} -ErrorAction Stop"
                     + (a.Start ? $"; Start-Service -Name '{a.Name}' -ErrorAction Stop" : ""),
        "account" => "try { Disable-LocalUser -Name 'Gast' -ErrorAction Stop } catch { Disable-LocalUser -Name 'Guest' -ErrorAction Stop }",
        "auditpol" => $"auditpol /set /subcategory:'{{{a.Subcategory}}}' /success:{Flag(a.Success)} /failure:{Flag(a.Failure)}; if($LASTEXITCODE -ne 0){{exit 1}}",
        "eventlog" => $"wevtutil sl {a.Log} /ms:{a.MaxSizeBytes}; if($LASTEXITCODE -ne 0){{exit 1}}",
        "firewallProfile" => $"Set-NetFirewallProfile -Profile {a.Profile} -Enabled {(a.Enabled == true ? "True" : "False")} -ErrorAction Stop",
        "smb" => "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop",
        "netaccounts" => $"net accounts /{a.Switch}:{a.Value}; if($LASTEXITCODE -ne 0){{exit 1}}",
        "secedit" => SeceditApply(a),
        _ => throw new InvalidOperationException($"unknown remediation type '{a.Type}'"),
    };

    private static string Flag(bool? b) => b == true ? "enable" : "disable";

    private static string RegistryApply(RemediationAction a)
    {
        var p = PsPath(a.Key!);
        return $"New-Item -Path '{p}' -Force -ErrorAction Stop | Out-Null; "
             + $"New-ItemProperty -Path '{p}' -Name '{a.ValueName}' -Value {ValueLiteral(a)} -PropertyType {PsPropertyType(a.ValueType)} -Force -ErrorAction Stop | Out-Null";
    }

    private static string SeceditApply(RemediationAction a)
    {
        var key = a.ValueName!;
        var val = a.Value!;
        return $$"""
            $ErrorActionPreference='Stop'
            $inf=[IO.Path]::Combine([IO.Path]::GetTempPath(),('wha-sec-' + [guid]::NewGuid().ToString('N') + '.inf'))
            $sdb=$inf + '.sdb'
            secedit /export /cfg $inf /areas SECURITYPOLICY | Out-Null
            if($LASTEXITCODE -ne 0){ throw ('secedit export failed: ' + $LASTEXITCODE) }
            $lines=[IO.File]::ReadAllLines($inf)
            $found=$false
            for($i=0;$i -lt $lines.Count;$i++){ if($lines[$i] -match '^{{key}}\s*='){ $lines[$i]='{{key}} = {{val}}'; $found=$true; break } }
            if(-not $found){
              $j=[array]::IndexOf($lines,'[System Access]')
              if($j -ge 0){ $lines=@($lines[0..$j]) + '{{key}} = {{val}}' + @($lines[($j+1)..($lines.Count-1)]) }
              else { $lines=@('[System Access]','{{key}} = {{val}}') + $lines }
            }
            [IO.File]::WriteAllLines($inf,$lines,[Text.Encoding]::Unicode)
            secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY /overwrite | Out-Null
            if($LASTEXITCODE -ne 0){ throw ('secedit configure failed: ' + $LASTEXITCODE) }
            Remove-Item $inf -ErrorAction SilentlyContinue
            Remove-Item $sdb -ErrorAction SilentlyContinue
            """;
    }

    // ---- snapshot (old value, run before applying) ---------------------------

    public static string Snapshot(RemediationAction a) => a.Type switch
    {
        "registry" => RegistrySnapshot(a),
        "service" => $"@{{type='service';startType=(Get-Service -Name '{a.Name}' -ErrorAction Stop).StartType.ToString()}} | ConvertTo-Json -Compress",
        "account" => "try { $e=(Get-LocalUser -Name 'Gast' -ErrorAction Stop).Enabled; $n='Gast' } catch { $e=(Get-LocalUser -Name 'Guest' -ErrorAction Stop).Enabled; $n='Guest' }; @{type='account';name=$n;enabled=$e} | ConvertTo-Json -Compress",
        "auditpol" => AuditpolSnapshot(a),
        "eventlog" => $"@{{type='eventlog';log='{a.Log}';bytes=(Get-WinEvent -ListLog {a.Log} -ErrorAction Stop).MaximumSizeInBytes}} | ConvertTo-Json -Compress",
        "firewallProfile" => $"@{{type='firewallProfile';profile='{a.Profile}';enabled=(Get-NetFirewallProfile -Profile {a.Profile} -ErrorAction Stop).Enabled}} | ConvertTo-Json -Compress",
        "smb" => "@{type='smb';enabled=(Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol} | ConvertTo-Json -Compress",
        "netaccounts" => NetAccountsSnapshot(a),
        "secedit" => "exit 0", // handled via the full export in RemediationRunner
        _ => throw new InvalidOperationException($"unknown remediation type '{a.Type}'"),
    };

    private static string RegistrySnapshot(RemediationAction a)
    {
        var p = PsPath(a.Key!);
        var name = a.ValueName!;
        return $$"""
            $ErrorActionPreference='Stop'
            $p='{{p}}'
            $k=Get-Item -Path $p -ErrorAction SilentlyContinue
            if($null -eq $k){ $r=@{existed=$false} } else {
              $v=$k.GetValue('{{name}}')
              if($null -eq $v){ $r=@{existed=$false} } else { $r=@{existed=$true;value=$v;kind=$k.GetValueKind('{{name}}').ToString()} }
            }
            $r | ConvertTo-Json -Compress
            """;
    }

    private static string AuditpolSnapshot(RemediationAction a)
    {
        var g = a.Subcategory!;
        return $$"""
            $g='{{g}}'
            $s='{' + $g + '}'
            $o=@(auditpol /get /subcategory:$s /r)
            if($LASTEXITCODE -ne 0){ exit 1 }
            $l=@($o | Where-Object { [string]$_ -match [regex]::Escape($g) } | Select-Object -First 1)
            if($l.Count -eq 0){ exit 1 }
            $v=([string]$l[0]).Split(',')[4].Trim()
            if([string]::IsNullOrWhiteSpace($v)){ exit 1 }
            @{type='auditpol';setting=$v} | ConvertTo-Json -Compress
            """;
    }

    private static string NetAccountsSnapshot(RemediationAction a)
    {
        var pat = NetAccountsPattern(a.Switch!);
        var sw = a.Switch!;
        return $$"""
            $pat='{{pat}}'
            $out=@(net accounts)
            $line=@($out | Where-Object { ([string]$_) -match $pat } | Select-Object -First 1)
            $val=''
            if($line.Count -gt 0 -and (([string]$line[0]).IndexOf(':') -ge 0)){
              $val=(((([string]$line[0]).Split(':',2))[1]).Trim())
            }
            @{type='netaccounts';switch='{{sw}}';value=$val} | ConvertTo-Json -Compress
            """;
    }

    private static string NetAccountsPattern(string sw) => sw switch
    {
        "minpwlen" => "minimum password length|minimales kennwort",
        "minpwage" => "minimum password age|minimales kennwortalter",
        "maxpwage" => "maximum password age|maximales kennwortalter",
        "uniquepw" => "password history|kennwortverlauf|unique password|eindeutiges",
        "lockoutthreshold" => "lockout threshold|sperrschwelle",
        "lockoutduration" => "lockout duration|sperrdauer",
        "lockoutwindow" => "lockout observation|beobachtungsfenster",
        _ => throw new InvalidOperationException($"unknown net accounts switch '{sw}'"),
    };

    // ---- undo (from snapshot) ------------------------------------------------

    public static string UndoFromSnapshot(RemediationAction a, string snapshot)
    {
        var doc = TryParse(snapshot, out var root) ? root : default;
        // Fail closed: an unusable snapshot must yield an empty script so the
        // caller aborts instead of running a guessed undo.
        return a.Type switch
        {
            "registry" => RegistryUndo(a, doc),
            "service" => string.IsNullOrWhiteSpace(Str(doc, "startType"))
                ? "" : $"Set-Service -Name '{a.Name}' -StartupType {Str(doc, "startType")} -ErrorAction Stop",
            "account" => AccountUndo(doc),
            "auditpol" => AuditpolUndo(a, Str(doc, "setting")),
            "eventlog" => Num(doc, "bytes") is long b ? $"wevtutil sl {a.Log} /ms:{b}; if($LASTEXITCODE -ne 0){{exit 1}}" : "",
            "firewallProfile" => Bool(doc, "enabled") is bool en
                ? $"Set-NetFirewallProfile -Profile {a.Profile} -Enabled {(en ? "True" : "False")} -ErrorAction Stop" : "",
            "smb" => Bool(doc, "enabled") is bool sm
                ? $"Set-SmbServerConfiguration -EnableSMB1Protocol {(sm ? "$true" : "$false")} -Force -ErrorAction Stop" : "",
            "netaccounts" => NetAccountsUndo(a, Str(doc, "value")),
            "secedit" => "exit 0", // handled via the secedit export entry
            _ => throw new InvalidOperationException($"unknown remediation type '{a.Type}'"),
        };
    }

    private static string RegistryUndo(RemediationAction a, JsonElement doc)
    {
        if (doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty("existed", out var ex) && ex.GetBoolean())
        {
            var p = PsPath(a.Key!);
            var kind = Str(doc, "kind") is { Length: > 0 } k ? k : "String";
            var value = ValueLiteral(doc, "value", kind);
            return $"New-Item -Path '{p}' -Force -ErrorAction Stop | Out-Null; "
                 + $"New-ItemProperty -Path '{p}' -Name '{a.ValueName}' -Value {value} -PropertyType {PsPropertyType(kind)} -Force -ErrorAction Stop | Out-Null";
        }
        return $"Remove-ItemProperty -Path '{PsPath(a.Key!)}' -Name '{a.ValueName}' -ErrorAction SilentlyContinue";
    }

    private static string AccountUndo(JsonElement doc)
    {
        var name = Str(doc, "name");
        if (name.Length == 0 || Bool(doc, "enabled") is not bool enabled) return "";
        return enabled
            ? $"Enable-LocalUser -Name '{name}' -ErrorAction Stop"
            : $"Disable-LocalUser -Name '{name}' -ErrorAction Stop";
    }

    private static string AuditpolUndo(RemediationAction a, string setting)
    {
        if (string.IsNullOrWhiteSpace(setting)) return "";
        var succ = setting.Contains("Success", StringComparison.OrdinalIgnoreCase)
                   || setting.Contains("Erfolg", StringComparison.OrdinalIgnoreCase);
        var fail = setting.Contains("Failure", StringComparison.OrdinalIgnoreCase)
                   || setting.Contains("Fehler", StringComparison.OrdinalIgnoreCase);
        return $"auditpol /set /subcategory:'{{{a.Subcategory}}}' /success:{(succ ? "enable" : "disable")} /failure:{(fail ? "enable" : "disable")}; if($LASTEXITCODE -ne 0){{exit 1}}";
    }

    private static string NetAccountsUndo(RemediationAction a, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        if (long.TryParse(value, out var n)) return $"net accounts /{a.Switch}:{n}; if($LASTEXITCODE -ne 0){{exit 1}}";
        // "Never"/"Niemals" (no expiry) maps to unlimited; other words cannot be restored automatically.
        return value.Trim().ToLowerInvariant() switch
        {
            "never" or "niemals" or "unlimited" when a.Switch == "maxpwage" => "net accounts /maxpwage:unlimited; if($LASTEXITCODE -ne 0){exit 1}",
            _ => "",
        };
    }

    // ---- helpers --------------------------------------------------------------

    private static string PsPath(string key)
    {
        var k = key.Trim();
        if (k.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)) return "HKLM:" + k[5..];
        if (k.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase)) return "HKCU:" + k[5..];
        return k;
    }

    private static string PsPropertyType(string? type) => (type ?? "").Trim().ToLowerInvariant() switch
    {
        "dword" => "DWord",
        "qword" => "QWord",
        "expandstring" or "expand" => "ExpandString",
        _ => "String",
    };

    private static string ValueLiteral(RemediationAction a)
        => ValueLiteral(a.Value ?? "", a.ValueType ?? "string");

    private static string ValueLiteral(string raw, string type)
    {
        var t = (type ?? "").Trim().ToLowerInvariant();
        if (t is "dword" or "qword" && long.TryParse(raw, out var n)) return n.ToString();
        return "'" + raw.Replace("'", "''") + "'";
    }

    private static string ValueLiteral(JsonElement doc, string prop, string kind)
    {
        if (!doc.TryGetProperty(prop, out var v)) return "''";
        if ((kind == "DWord" || kind == "QWord") && v.ValueKind == JsonValueKind.Number)
            return v.GetInt64().ToString();
        if (v.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
            return v.ToString();
        return "'" + v.ToString().Replace("'", "''") + "'";
    }

    private static bool TryParse(string json, out JsonElement root)
    {
        try
        {
            using var d = JsonDocument.Parse(json);
            root = d.RootElement.Clone();
            return root.ValueKind == JsonValueKind.Object;
        }
        catch
        {
            root = default;
            return false;
        }
    }

    private static string Str(JsonElement doc, string prop)
        => doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty(prop, out var v)
            ? (v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString())
            : "";

    private static long? Num(JsonElement doc, string prop)
        => doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetInt64()
            : null;

    private static bool? Bool(JsonElement doc, string prop)
        => doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty(prop, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? v.GetBoolean()
            : null;

    // ---- display (language-neutral technical summary for the guide dialog) ----

    /// <summary>
    /// Extracts a copyable command from a guide step, or null when the step is prose.
    /// Handles "PowerShell ...: &lt;command&gt;" prefixes and bare command lines.
    /// Strips narrative suffixes ("; Neustart", "; danach ...") and prose
    /// parentheses so the result can be pasted into a console as-is.
    /// </summary>
    public static string? TryExtractCommand(string step)
    {
        if (string.IsNullOrWhiteSpace(step)) return null;
        var s = step.Trim();
        string? candidate = null;
        var ps = s.IndexOf("PowerShell", StringComparison.OrdinalIgnoreCase);
        if (ps >= 0)
        {
            var colon = s.IndexOf(':', ps);
            if (colon >= 0 && colon + 1 < s.Length)
                candidate = s[(colon + 1)..].Trim();
        }
        else
        {
            foreach (var prefix in new[]
            {
                "Get-", "Set-", "New-", "Remove-", "Revoke-", "Enable-", "Disable-",
                "Update-", "Start-", "Stop-", "Test-", "Confirm-", "auditpol", "secedit",
                "gpupdate", "gpresult", "net ", "wevtutil", "edge://", "certmgr",
                "tpm.msc", "services.msc", "lusrmgr", "compmgmt", "eventvwr",
            })
            {
                if (s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    candidate = s;
                    break;
                }
            }
            // "Do X: <command>" prose prefix with the command at the end.
            if (candidate is null)
            {
                var lastColon = s.LastIndexOf(':');
                if (lastColon >= 0 && lastColon + 1 < s.Length)
                {
                    var tail = s[(lastColon + 1)..].Trim();
                    foreach (var prefix in new[]
                    {
                        "Get-", "Set-", "New-", "Remove-", "Revoke-", "Enable-", "Disable-",
                        "Update-", "Start-", "Stop-", "Test-", "Confirm-", "auditpol", "secedit",
                        "gpupdate", "gpresult", "net ", "wevtutil",
                    })
                    {
                        if (tail.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            candidate = tail;
                            break;
                        }
                    }
                }
            }
        }
        if (string.IsNullOrWhiteSpace(candidate)) return null;
        var cmd = candidate.Trim();
        // Cut narrative suffixes: "; Neustart", "; danach ...", "; erneut scannen", ... .
        var cut = System.Text.RegularExpressions.Regex.Match(
            cmd, @";\s*(neustart|danach|restart|then|erneut|erneuter|verify|re-scan|rescan|prüfen|pruefen)\b.*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (cut.Success) cmd = cmd[..cut.Index].Trim();
        // Strip prose parentheses (they contain whitespace; code parens like
        // "(Get-MpComputerStatus)" have none and are kept).
        cmd = System.Text.RegularExpressions.Regex.Replace(cmd, @"\([^()]*\s[^()]*\)", "").Trim();
        // Strip "(Admin)"-style elevation markers.
        cmd = System.Text.RegularExpressions.Regex.Replace(
            cmd, @"\s*\((admin|administrator)\)", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();
        // Strip a trailing "(...)" remark such as "(Admin)".
        cmd = System.Text.RegularExpressions.Regex.Replace(cmd, @"\s*\([^()]*\)\.?$", "").Trim();
        cmd = System.Text.RegularExpressions.Regex.Replace(cmd, @"\s{2,}", " ").Trim();
        cmd = cmd.TrimEnd('.').Trim();
        return cmd.Length > 0 ? cmd : null;
    }

    public static string Describe(RemediationAction a) => a.Type switch
    {
        "registry" => $"Registry: {a.Key}\\{a.ValueName} = {a.Value} ({a.ValueType})",
        "service" => $"Service: {a.Name} -> startup {a.StartType}" + (a.Start ? " + start" : ""),
        "account" => $"Account: disable '{a.Name}'",
        "auditpol" => $"auditpol: {a.Subcategory} success={Flag(a.Success)} failure={Flag(a.Failure)}",
        "eventlog" => $"Event log: {a.Log} max size {a.MaxSizeBytes} bytes",
        "firewallProfile" => $"Firewall profile: {a.Profile} -> {(a.Enabled == true ? "on" : "off")}",
        "smb" => "SMB: disable SMBv1 server",
        "netaccounts" => $"Accounts policy: net accounts /{a.Switch}:{a.Value}",
        "secedit" => $"Security policy: {a.ValueName} = {a.Value}",
        _ => a.Type,
    };
}

/// <summary>Runs PowerShell scripts via a temp .ps1 file (no Escape() pitfalls, multi-line safe).</summary>
public static class PowerShellFile
{
    public static async Task<(bool Ok, string Text)> RunAsync(string script, CancellationToken ct = default)
    {
        var file = Path.Combine(Path.GetTempPath(), "wha-" + Guid.NewGuid().ToString("N") + ".ps1");
        await File.WriteAllTextAsync(file, script, ct);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{file}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return (false, "process start failed");
            var stdout = await p.StandardOutput.ReadToEndAsync(ct);
            var stderr = await p.StandardError.ReadToEndAsync(ct);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMinutes(3));
            try { await p.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) { try { p.Kill(); } catch { } return (false, "timeout"); }
            var text = (stdout + (stderr.Length > 0 ? "\r\n" + stderr : "")).Trim();
            return (p.ExitCode == 0, text);
        }
        finally
        {
            try { File.Delete(file); } catch { }
        }
    }
}
