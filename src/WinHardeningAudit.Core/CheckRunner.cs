using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using WinHardeningAudit.Core.Models;

namespace WinHardeningAudit.Core.Engine;

public sealed class CheckRunner
{
    private readonly Dictionary<string, ICheckProvider> _providers;

    public CheckRunner(IEnumerable<ICheckProvider>? providers = null)
    {
        List<ICheckProvider> list = providers?.ToList() ?? new List<ICheckProvider> { new RegistryProvider(), new ScriptProvider(), new SeceditProvider(), new ManualProvider() };
        _providers = list.ToDictionary(p => p.Name, StringComparer.OrdinalIgnoreCase);
    }

    private static bool? _elevatedCache;

    public static bool IsElevated()
    {
        _elevatedCache ??= CheckElevated();
        return _elevatedCache.Value;
    }

    private static bool CheckElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            var p = new WindowsPrincipal(id);
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static void RelaunchAsAdmin(string args = "--elevated")
    {
        var exe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
        if (exe is null) throw new InvalidOperationException("Exe-Pfad unbekannt");
        var psi = new ProcessStartInfo { FileName = exe, Arguments = args, UseShellExecute = true, Verb = "runas" };
        Process.Start(psi);
    }

    public async Task<ScanReport> RunAsync(IEnumerable<RuleDefinition> rules, CancellationToken ct = default, int maxParallel = 8)
    {
        var ruleList = rules.ToList();
        var results = new CheckResult?[ruleList.Count];
        using var throttler = new SemaphoreSlim(Math.Max(1, maxParallel));
        var tasks = ruleList.Select(async (rule, idx) =>
        {
            await throttler.WaitAsync(ct);
            try
            {
                var sw = Stopwatch.StartNew();
                var provider = _providers.TryGetValue(rule.Check.Provider, out var p) ? p : _providers["manual"];
                var outcome = await provider.EvaluateAsync(rule, ct);
                sw.Stop();
                results[idx] = new CheckResult
                {
                    Rule = rule,
                    Status = outcome.Status,
                    ActualValue = outcome.ActualValue,
                    ExpectedValue = rule.Check.Expected,
                    Message = outcome.Message,
                    DurationMs = sw.ElapsedMilliseconds,
                    ManualKind = outcome.ManualKind,
                };
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                results[idx] = new CheckResult
                {
                    Rule = rule,
                    Status = CheckStatus.Error,
                    ExpectedValue = rule.Check.Expected,
                    Message = $"Provider exception caught: {ex.Message}",
                };
            }
            finally { throttler.Release(); }
        });
        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // Cancelled slots stay null and are filtered out below.
        }

        var list = results.Where(r => r is not null).Cast<CheckResult>().ToList();
        var passed = list.Count(r => r.Status == CheckStatus.Passed);
        var failed = list.Count(r => r.Status == CheckStatus.Failed);
        var manual = list.Count(r => r.Status is CheckStatus.Manual or CheckStatus.NotApplicable or CheckStatus.Warning);
        var errors = list.Count(r => r.Status == CheckStatus.Error);
        var denom = Math.Max(1, passed + failed);
        return new ScanReport
        {
            IsElevated = IsElevated(),
            Results = list
                .OrderByDescending(r => r.Rule.Severity)
                .ThenBy(r => r.Status == CheckStatus.Passed ? 1 : 0)
                .ToList(),
            Summary = new ScanSummary
            {
                Total = list.Count,
                Passed = passed,
                Failed = failed,
                Manual = manual,
                Errors = errors,
                CriticalOpen = list.Count(r => r.Rule.Severity == Severity.Critical && r.Status == CheckStatus.Failed),
                HighOpen = list.Count(r => r.Rule.Severity == Severity.High && r.Status == CheckStatus.Failed),
                ScorePercent = Math.Round(100.0 * passed / denom, 1)
            }
        };
    }

    public static List<RuleDefinition> LoadRulesFromDirectory(string dir, string? language = null)
    {
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var rules = new List<RuleDefinition>();
        if (!Directory.Exists(dir)) return rules;
        foreach (var file in Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories))
        {
            // Localization overlays (Rules/l10n/*.json) are merged, not loaded as rules.
            if (file.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .Any(s => string.Equals(s, "l10n", StringComparison.OrdinalIgnoreCase)))
                continue;
            try
            {
                var json = File.ReadAllText(file);
                var batch = JsonSerializer.Deserialize<List<RuleDefinition>>(json, options);
                if (batch is not null) rules.AddRange(batch);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Skipped rule file ({file}): {ex.Message}");
            }
        }
        return ApplyOverlay(rules, dir, language ?? CoreStrings.Language);
    }

    /// <summary>
    /// Merges localized rule texts from Rules/l10n/&lt;lang&gt;.json ({ruleId: {title, description, fixHint, note}}).
    /// Unknown IDs are ignored; missing entries fall back to the rule-file language (German).
    /// </summary>
    public static List<RuleDefinition> ApplyOverlay(List<RuleDefinition> rules, string dir, string language)
    {
        if (string.IsNullOrWhiteSpace(language) || language.Trim().ToLowerInvariant() == "de")
            return rules;
        var overlayFile = Path.Combine(dir, "l10n", language.Trim().ToLowerInvariant() + ".json");
        if (!File.Exists(overlayFile)) return rules;
        Dictionary<string, RuleOverlay>? overlay;
        try
        {
            overlay = JsonSerializer.Deserialize<Dictionary<string, RuleOverlay>>(
                File.ReadAllText(overlayFile),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Skipped rule overlay ({overlayFile}): {ex.Message}");
            return rules;
        }
        if (overlay is null || overlay.Count == 0) return rules;
        return rules.Select(r =>
        {
            if (!overlay.TryGetValue(r.Id, out var o) || o is null) return r;
            return r with
            {
                Title = string.IsNullOrWhiteSpace(o.Title) ? r.Title : o.Title,
                Description = string.IsNullOrWhiteSpace(o.Description) ? r.Description : o.Description,
                FixHint = string.IsNullOrWhiteSpace(o.FixHint) ? r.FixHint : o.FixHint,
                Notiz26H2 = string.IsNullOrWhiteSpace(o.Note) ? r.Notiz26H2 : o.Note,
            };
        }).ToList();
    }

    public sealed record RuleOverlay
    {
        public string? Title { get; init; }
        public string? Description { get; init; }
        public string? FixHint { get; init; }
        public string? Note { get; init; }
    }

    public static readonly string[] ValidProfile = { "L1", "L2", "MS" };
    public static readonly string[] ValidZiel = { "both", "standalone", "enterprise" };
    public static readonly string[] ValidProviders = { "registry", "script", "secedit", "manual" };
    public static readonly string[] ValidCategories =
    {
        "accounts-uac", "defender-malware", "bitlocker-encryption",
        "firewall-network", "secureboot-vbs", "updates-maintenance",
        "audit-logging", "system-hardening", "browser-edge",
        "user-rights", "services",
    };
    public static readonly string[] ValidOperators =
    {
        "Equals", "NotEquals", "Contains", "ContainsAll", "GreaterOrEqual", "LessOrEqual", "Between",
    };
    public static readonly string[] ValidSeceditKeys = { "SystemAccess", "PrivilegeRights" };

    public static List<string> ValidateRules(IEnumerable<RuleDefinition> rules)
    {
        var problems = new List<string>();
        var list = rules.ToList();
        foreach (var dup in list.GroupBy(r => r.Id).Where(g => g.Count() > 1).Select(g => g.Key))
            problems.Add($"Duplicate ID: {dup}");
        foreach (var r in list)
        {
            if (string.IsNullOrWhiteSpace(r.Id)) problems.Add("Rule without ID");
            if (string.IsNullOrWhiteSpace(r.Title)) problems.Add($"Rule {r.Id}: without title");
            if (string.IsNullOrWhiteSpace(r.Category)) problems.Add($"Rule {r.Id}: without category");
            if (!ValidCategories.Contains(r.Category)) problems.Add($"Rule {r.Id}: unknown category '{r.Category}'");
            if (!Enum.IsDefined(typeof(Severity), r.Severity)) problems.Add($"Rule {r.Id}: invalid severity '{(int)r.Severity}'");
            if (!ValidProfile.Contains(r.Profil ?? "L1"))
                problems.Add($"Rule {r.Id}: invalid profile '{r.Profil}'");
            if (!ValidZiel.Contains((r.Ziel ?? "both").Trim().ToLowerInvariant()))
                problems.Add($"Rule {r.Id}: invalid target '{r.Ziel}'");
            var provider = (r.Check.Provider ?? "").Trim().ToLowerInvariant();
            if (!ValidProviders.Contains(provider)) problems.Add($"Rule {r.Id}: unknown provider '{r.Check.Provider}'");
            if (!ValidOperators.Contains(r.Check.Operator)) problems.Add($"Rule {r.Id}: unknown operator '{r.Check.Operator}'");
            switch (provider)
            {
                case "registry":
                    if (string.IsNullOrWhiteSpace(r.Check.Key)) problems.Add($"Rule {r.Id}: registry without key");
                    if (string.IsNullOrWhiteSpace(r.Check.ValueName)) problems.Add($"Rule {r.Id}: registry without value name");
                    if (r.Check.Expected is null) problems.Add($"Rule {r.Id}: registry without expected value");
                    break;
                case "script":
                    if (string.IsNullOrWhiteSpace(r.Check.Script)) problems.Add($"Rule {r.Id}: script without code");
                    if (r.Check.Expected is null) problems.Add($"Rule {r.Id}: script without expected value");
                    break;
                case "secedit":
                    if (!ValidSeceditKeys.Any(k => string.Equals(k, r.Check.Key, StringComparison.OrdinalIgnoreCase)))
                        problems.Add($"Rule {r.Id}: secedit with invalid key '{r.Check.Key}'");
                    if (string.IsNullOrWhiteSpace(r.Check.ValueName)) problems.Add($"Rule {r.Id}: secedit without value name");
                    if (r.Check.Expected is null) problems.Add($"Rule {r.Id}: secedit without expected value");
                    break;
            }
        }
        return problems;
    }
}
