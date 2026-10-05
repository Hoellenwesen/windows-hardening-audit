using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using WinHardeningAudit.Core.Models;

namespace WinHardeningAudit.Core.Engine;

public sealed record ProviderOutcome(CheckStatus Status, string? ActualValue, string Message, string ManualKind = "");

/// <summary>
/// User-facing engine strings. Defaults are English; the WinUI app installs a
/// German override at startup (<c>CoreStrings.Override</c>) when the UI language
/// is German. <c>Language</c> also drives rule-overlay selection in <see cref="CheckRunner"/>.
/// </summary>
public static class CoreStrings
{
    private static readonly Dictionary<string, string> _en = new(StringComparer.Ordinal)
    {
        ["RegKeyMissing"] = "Registry key missing: {0}",
        ["RegValueMissing"] = "Value '{0}' missing in {1}",
        ["MatchOk"] = "Expected = actual",
        ["Mismatch"] = "Expected {0} {1}, actual {2}",
        ["AccessDenied"] = "Access denied (admin rights required): {0}",
        ["MissingPassed"] = "{0} – treated as OK (secure default).",
        ["MissingManual"] = "{0} – please review manually (no policy set).",
        ["ScriptMissing"] = "No script defined",
        ["ScriptStartFailed"] = "PowerShell could not be started",
        ["ScriptError"] = "Script error (admin rights may be required): {0}",
        ["NotApplicable"] = "Not applicable on this device or edition (e.g. no TPM, no Secure Boot in VM, no Enterprise).",
        ["ManualDefault"] = "Manual review required (judgment call – see guidance).",
        ["SeceditFailed"] = "secedit export failed (admin rights may be required): {0}",
        ["SeceditSectionMissing"] = "Section '{0}' not found in secedit export",
        ["SeceditPassed"] = "'{0}' is not configured – treated as OK (secure default).",
        ["SeceditNotSet"] = "'{0}' is not configured, expected {1} {2}",
        ["NetAccountsOk"] = "Expected = actual (source: net accounts, no admin)",
        ["NetAccountsMismatch"] = "Expected {0} {1}, actual {2} (source: net accounts)",
        ["ValueMissing"] = "(missing)",
        ["ValueNotConfigured"] = "(not configured)",
        ["ValueNotSet"] = "(not set)",
        ["ValueEmpty"] = "(empty)",
    };

    /// <summary>Active UI language: "de" (rule-file language, default) or "en".</summary>
    public static string Language { get; set; } = "de";

    /// <summary>Optional app-installed lookup (e.g. from .resw). Null or the key itself falls back to English.</summary>
    public static Func<string, string?>? Override { get; set; }

    public static string Get(string key)
    {
        if (Override is not null)
        {
            try
            {
                var s = Override(key);
                if (!string.IsNullOrEmpty(s) && s != key) return s;
            }
            catch { }
        }
        return _en.TryGetValue(key, out var v) ? v : key;
    }

    public static string F(string key, params object[] args)
    {
        try { return string.Format(Get(key), args); }
        catch { return Get(key); }
    }
}

public interface ICheckProvider
{
    string Name { get; }
    Task<ProviderOutcome> EvaluateAsync(RuleDefinition rule, CancellationToken ct);
}

public sealed class RegistryProvider : ICheckProvider
{
    public string Name => "registry";

    public Task<ProviderOutcome> EvaluateAsync(RuleDefinition rule, CancellationToken ct)
    {
        var spec = rule.Check;
        try
        {
            using var baseKey = spec.Key.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)
                ? Registry.LocalMachine
                : spec.Key.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase)
                    ? Registry.CurrentUser
                    : Registry.LocalMachine;

            var subPath = spec.Key.Contains('\\')
                ? spec.Key[(spec.Key.IndexOf('\\') + 1)..]
                : spec.Key;

            using var key = baseKey.OpenSubKey(subPath, false);
            if (key is null)
                return Task.FromResult(Missing(spec, CoreStrings.F("RegKeyMissing", spec.Key)));

            var raw = key.GetValue(spec.ValueName);
            if (raw is null)
                return Task.FromResult(Missing(spec, CoreStrings.F("RegValueMissing", spec.ValueName, spec.Key)));

            var actual = raw switch
            {
                int i => i.ToString(),
                long l => l.ToString(),
                byte[] b => BitConverter.ToString(b).Replace("-", ""),
                string[] sa => string.Join("; ", sa),
                _ => raw.ToString() ?? "",
            };
            var ok = Compare(actual, spec.Expected ?? "", spec.Operator);
            return Task.FromResult(ok
                ? new ProviderOutcome(CheckStatus.Passed, actual, CoreStrings.Get("MatchOk"))
                : new ProviderOutcome(CheckStatus.Failed, actual, CoreStrings.F("Mismatch", spec.Operator, spec.Expected, actual)));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Task.FromResult(new ProviderOutcome(CheckStatus.Manual, null, CoreStrings.F("AccessDenied", ex.Message), "admin-environment"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new ProviderOutcome(CheckStatus.Error, null, ex.Message));
        }
    }

    public static bool Compare(string actual, string expected, string op)
    {
        var a = actual.Trim();
        var e = (expected ?? "").Trim();
        return op switch
        {
            "Equals" => string.Equals(a, e, StringComparison.OrdinalIgnoreCase),
            "NotEquals" => !string.Equals(a, e, StringComparison.OrdinalIgnoreCase),
            "Contains" => a.Contains(e, StringComparison.OrdinalIgnoreCase),
            "GreaterOrEqual" => TryLong(a, out var la) && TryLong(e, out var le) && la >= le,
            "LessOrEqual" => TryLong(a, out var la2) && TryLong(e, out var le2) && la2 <= le2,
            _ => string.Equals(a, e, StringComparison.OrdinalIgnoreCase),
        };
    }

    private static bool TryLong(string s, out long v)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(s[2..], System.Globalization.NumberStyles.HexNumber, null, out v);
        return long.TryParse(s, out v);
    }

    private static ProviderOutcome Missing(CheckSpec spec, string message)
    {
        return (spec.MissingIs ?? "Failed").Trim().ToLowerInvariant() switch
        {
            "passed" => new ProviderOutcome(CheckStatus.Passed, CoreStrings.Get("ValueNotConfigured"), CoreStrings.F("MissingPassed", message)),
            "manual" => new ProviderOutcome(CheckStatus.Manual, null, CoreStrings.F("MissingManual", message), "policy-missing"),
            _ => new ProviderOutcome(CheckStatus.Failed, CoreStrings.Get("ValueMissing"), message),
        };
    }
}

public sealed class ScriptProvider : ICheckProvider
{
    public string Name => "script";

    public async Task<ProviderOutcome> EvaluateAsync(RuleDefinition rule, CancellationToken ct)
    {
        var spec = rule.Check;
        if (string.IsNullOrWhiteSpace(spec.Script))
            return new ProviderOutcome(CheckStatus.Error, null, CoreStrings.Get("ScriptMissing"));

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + Escape(spec.Script) + "\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null)
                return new ProviderOutcome(CheckStatus.Error, null, CoreStrings.Get("ScriptStartFailed"));
            var outputTask = p.StandardOutput.ReadToEndAsync(ct);
            var errorTask = p.StandardError.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            var output = (await outputTask).Trim();
            var error = (await errorTask).Trim();
            if (p.ExitCode != 0 && string.IsNullOrEmpty(output))
                return new ProviderOutcome(CheckStatus.Manual, null, CoreStrings.F("ScriptError", error), "admin-environment");

            var actual = string.IsNullOrEmpty(output) ? CoreStrings.Get("ValueEmpty") : output.Split('\n')[0].Trim();
            if (string.Equals(actual, "N/A", StringComparison.OrdinalIgnoreCase))
                return new ProviderOutcome(CheckStatus.NotApplicable, null, CoreStrings.Get("NotApplicable"));
            var ok = RegistryProvider.Compare(actual, spec.Expected ?? "", spec.Operator);
            return ok
                ? new ProviderOutcome(CheckStatus.Passed, actual, CoreStrings.Get("MatchOk"))
                : new ProviderOutcome(CheckStatus.Failed, actual, CoreStrings.F("Mismatch", spec.Operator, spec.Expected, actual));
        }
        catch (Exception ex)
        {
            return new ProviderOutcome(CheckStatus.Error, null, ex.Message);
        }
    }

    private static string Escape(string s) => s.Replace("\"", "'");
}

public sealed class ManualProvider : ICheckProvider
{
    public string Name => "manual";
    public Task<ProviderOutcome> EvaluateAsync(RuleDefinition rule, CancellationToken ct)
        => Task.FromResult(new ProviderOutcome(CheckStatus.Manual, null, CoreStrings.Get("ManualDefault"), "discretion"));
}

public sealed class SeceditProvider : ICheckProvider
{
    public string Name => "secedit";

    private readonly object _exportLock = new();
    private Task<Dictionary<string, Dictionary<string, string>>>? _exportTask;

    public SeceditProvider()
    {
    }

    private Task<Dictionary<string, Dictionary<string, string>>> GetExportAsync()
    {
        lock (_exportLock)
        {
            if (_exportTask is null || (_exportTask.IsCompleted && _exportTask.IsFaulted))
                _exportTask = RunExport();
            return _exportTask;
        }
    }

    public async Task<ProviderOutcome> EvaluateAsync(RuleDefinition rule, CancellationToken ct)
    {
        var spec = rule.Check;
        Dictionary<string, Dictionary<string, string>> sections;
        try
        {
            sections = await GetExportAsync();
        }
        catch (Exception ex)
        {
            // Fallback without admin: System Access values via "net accounts" (EN+DE)
            if (IsSystemAccess(spec))
            {
                var fb = await TryNetAccountsAsync(spec.ValueName, spec.Expected ?? "", spec.Operator, ct);
                if (fb is not null) return fb;
            }
            return new ProviderOutcome(CheckStatus.Manual, null, CoreStrings.F("SeceditFailed", ex.Message), "admin-environment");
        }

        var sectionKey = (spec.Key ?? "").Trim().ToLowerInvariant() switch
        {
            "systemaccess" or "system access" or "" => "System Access",
            "privilegerights" or "privilege rights" => "Privilege Rights",
            _ => spec.Key
        };
        if (!sections.TryGetValue(sectionKey ?? "System Access", out var section))
            return new ProviderOutcome(CheckStatus.Error, null, CoreStrings.F("SeceditSectionMissing", sectionKey));

        if (!section.TryGetValue(spec.ValueName, out var actualRaw))
        {
            // Missing entry = not configured (secure OS default)
            if ((spec.MissingIs ?? "Failed").Trim().ToLowerInvariant() == "passed")
                return new ProviderOutcome(CheckStatus.Passed, CoreStrings.Get("ValueNotConfigured"), CoreStrings.F("SeceditPassed", spec.ValueName));
            return new ProviderOutcome(CheckStatus.Failed, CoreStrings.Get("ValueNotSet"), CoreStrings.F("SeceditNotSet", spec.ValueName, spec.Operator, spec.Expected));
        }

        var ok = CompareSecedit(actualRaw, spec.Expected ?? "", spec.Operator);
        var display = sectionKey == "Privilege Rights" ? TranslateSids(actualRaw) : actualRaw;
        return ok
            ? new ProviderOutcome(CheckStatus.Passed, display, CoreStrings.Get("MatchOk"))
            : new ProviderOutcome(CheckStatus.Failed, display, CoreStrings.F("Mismatch", spec.Operator, spec.Expected, display));
    }

    private static bool IsSystemAccess(CheckSpec spec)
        => string.IsNullOrWhiteSpace(spec.Key)
            || spec.Key.Trim().ToLowerInvariant() is "systemaccess" or "system access";

    private static readonly Dictionary<string, string[]> NetAccountsLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MinimumPasswordAge"] = new[] { "minimum password age", "minimales kennwortalter" },
        ["MaximumPasswordAge"] = new[] { "maximum password age", "maximales kennwortalter" },
        ["MinimumPasswordLength"] = new[] { "minimum password length", "minimale kennwort" },
        ["PasswordHistorySize"] = new[] { "password history", "kennwortverlauf" },
        ["LockoutBadCount"] = new[] { "lockout threshold", "sperrschwelle" },
        ["LockoutDuration"] = new[] { "lockout duration", "sperrdauer" },
        ["ResetLockoutCount"] = new[] { "lockout observation", "beobachtung" },
    };

    private static async Task<ProviderOutcome?> TryNetAccountsAsync(string valueName, string expected, string op, CancellationToken ct)
    {
        if (!NetAccountsLabels.TryGetValue(valueName ?? "", out var labels))
            return null;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "net.exe",
                Arguments = "accounts",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;
            var output = await p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            foreach (var line in output.Split('\n'))
            {
                var l = line.Trim().ToLowerInvariant();
                if (!labels.Any(l.Contains)) continue;
                // value after the colon: "Label:  value"
                var valuePart = line.Contains(':') ? line[(line.IndexOf(':') + 1)..].Trim() : line.Trim();
                var v = System.Text.RegularExpressions.Regex.Match(valuePart, @"^\d+").Success
                    ? System.Text.RegularExpressions.Regex.Match(valuePart, @"^\d+").Value
                    : valuePart;
                if (v.Equals("never", StringComparison.OrdinalIgnoreCase) || v.Equals("niemals", StringComparison.OrdinalIgnoreCase) || v.Equals("nie", StringComparison.OrdinalIgnoreCase))
                    v = "999999";
                if (v.Equals("none", StringComparison.OrdinalIgnoreCase) || v.Equals("keine", StringComparison.OrdinalIgnoreCase) || v.Equals("keiner", StringComparison.OrdinalIgnoreCase) || v.Equals("no", StringComparison.OrdinalIgnoreCase) || v.Equals("nein", StringComparison.OrdinalIgnoreCase))
                    v = "0";
                var ok = CompareSecedit(v, expected, op);
                return ok
                    ? new ProviderOutcome(CheckStatus.Passed, v, "Soll = Ist (Quelle: net accounts, ohne Admin)")
                    : new ProviderOutcome(CheckStatus.Failed, v, $"Erwartet {op} {expected}, ist {v} (Quelle: net accounts)");
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    public static bool CompareSecedit(string actual, string expected, string op)
    {
        var a = actual.Trim();
        var e = (expected ?? "").Trim();
        return op switch
        {
            "Contains" => SplitSids(a).Contains(NormSid(e), StringComparer.OrdinalIgnoreCase),
            "ContainsAll" => SplitSids(e).All(x => SplitSids(a).Contains(x, StringComparer.OrdinalIgnoreCase)),
            "GreaterOrEqual" => long.TryParse(a, out var la) && long.TryParse(e, out var le) && la >= le,
            "LessOrEqual" => long.TryParse(a, out var la2) && long.TryParse(e, out var le2) && la2 <= le2,
            _ => SetEquals(a, e),
        };
    }

    private static bool SetEquals(string a, string e)
    {
        if (!a.Contains(',') && !e.Contains(','))
            return string.Equals(a.Trim(), e.Trim(), StringComparison.OrdinalIgnoreCase);
        var sa = SplitSids(a);
        var se = SplitSids(e);
        return sa.Count == se.Count && se.All(x => sa.Contains(x, StringComparer.OrdinalIgnoreCase));
    }

    private static List<string> SplitSids(string s)
        => s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(NormSid).Where(x => x.Length > 0).ToList();

    private static string NormSid(string s)
    {
        s = s.Trim();
        if (s.StartsWith("*")) s = s[1..];
        return s;
    }

    public static string TranslateSids(string raw)
    {
        var parts = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(", ", parts.Select(p =>
        {
            var n = NormSid(p);
            return SidNames.TryGetValue(n, out var name) ? name : n;
        }));
    }

    private static readonly Dictionary<string, string> SidNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["S-1-5-32-544"] = "Administrators",
        ["S-1-5-32-545"] = "Users",
        ["S-1-5-32-546"] = "Guests",
        ["S-1-5-32-547"] = "Power Users",
        ["S-1-5-32-548"] = "Account Operators",
        ["S-1-5-32-549"] = "Server Operators",
        ["S-1-5-32-550"] = "Print Operators",
        ["S-1-5-32-551"] = "Backup Operators",
        ["S-1-5-32-552"] = "Replicators",
        ["S-1-5-32-555"] = "Remote Desktop Users",
        ["S-1-5-32-556"] = "Network Configuration Operators",
        ["S-1-5-32-557"] = "Incoming Forest Trust Builders",
        ["S-1-5-32-558"] = "Performance Log Users",
        ["S-1-5-113"] = "Local account (NT AUTHORITY)",
        ["S-1-5-32-554"] = "Pre-Windows 2000 Compatible Access",
        ["S-1-5-32-559"] = "Performance Monitor Users",
        ["S-1-5-32-562"] = "Distributed COM Users",
        ["S-1-5-32-569"] = "Cryptographic Operators",
        ["S-1-5-32-573"] = "Event Log Readers",
        ["S-1-5-32-575"] = "Hyper-V Administrators",
        ["S-1-5-32-576"] = "Certificate Publishers",
        ["S-1-5-32-578"] = "Virtual mode read access",
        ["S-1-5-32-580"] = "Remote Management Users",
        ["S-1-5-19"] = "LOCAL SERVICE",
        ["S-1-5-20"] = "NETWORK SERVICE",
        ["S-1-5-6"] = "SERVICE",
        ["S-1-5-90-0"] = "Window Manager",
        ["S-1-1-0"] = "Everyone",
        ["S-1-5-11"] = "Authenticated Users",
        ["S-1-5-18"] = "LOCAL SYSTEM",
        ["S-1-2-0"] = "LOCAL",
        ["S-1-2-1"] = "CONSOLE LOGON",
        ["S-1-5-64-10"] = "NTLM Authentication",
    };

    private static async Task<Dictionary<string, Dictionary<string, string>>> RunExport()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"wha-secedit-{Guid.NewGuid():N}.inf");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "secedit.exe",
                Arguments = $"/export /cfg \"{tmp}\" /quiet",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("secedit konnte nicht gestartet werden");
            await p.WaitForExitAsync();
            if (!File.Exists(tmp))
                throw new InvalidOperationException("secedit hat keine Exportdatei erzeugt");
            return ParseInf(await File.ReadAllTextAsync(tmp));
        }
        finally
        {
            try { File.Delete(tmp); } catch { }
        }
    }

    public static Dictionary<string, Dictionary<string, string>> ParseInf(string text)
    {
        var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string>? current = null;
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim().TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith(';')) continue;
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                var name = line[1..^1].Trim();
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                result[name] = current;
            }
            else if (current is not null)
            {
                var idx = line.IndexOf('=');
                if (idx > 0)
                    current[line[..idx].Trim()] = line[(idx + 1)..].Trim().Trim('"');
            }
        }
        return result;
    }
}
