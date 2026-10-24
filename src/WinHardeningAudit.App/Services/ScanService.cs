using WinHardeningAudit.Core.Engine;
using WinHardeningAudit.Core.Export;
using WinHardeningAudit.Core.Models;

namespace WinHardeningAudit_App.Services;

public sealed class ScanService
{
    public static ScanService Current { get; } = new();

    /// <summary>Language-neutral category keys; display names come from UI resources (Cat*).</summary>
    public static readonly string[] Categories =
    {
        "accounts-uac",
        "defender-malware",
        "bitlocker-encryption",
        "firewall-network",
        "secureboot-vbs",
        "updates-maintenance",
        "audit-logging",
        "system-hardening",
        "browser-edge",
        "user-rights",
        "services",
    };

    /// <summary>Language-neutral profile keys: l1, l1l2, ms, all.</summary>
    public static readonly string[] Profiles = { "l1", "l1l2", "ms", "all" };
    /// <summary>Language-neutral target keys: standalone, both, enterprise.</summary>
    public static readonly string[] Targets = { "standalone", "both", "enterprise" };

    public static string CategoryLabel(string key) => key switch
    {
        "accounts-uac" => L.Get("CatAccountsUac"),
        "defender-malware" => L.Get("CatDefenderMalware"),
        "bitlocker-encryption" => L.Get("CatBitlockerEncryption"),
        "firewall-network" => L.Get("CatFirewallNetwork"),
        "secureboot-vbs" => L.Get("CatSecurebootVbs"),
        "updates-maintenance" => L.Get("CatUpdatesMaintenance"),
        "audit-logging" => L.Get("CatAuditLogging"),
        "system-hardening" => L.Get("CatSystemHardening"),
        "browser-edge" => L.Get("CatBrowserEdge"),
        "user-rights" => L.Get("CatUserRights"),
        "services" => L.Get("CatServices"),
        _ => key,
    };

    // Display labels (localized) <-> canonical keys
    public static string ProfileLabel(string canonical) => canonical switch
    {
        "l1" => L.Get("ProfileL1"),
        "l1l2" => L.Get("ProfileL1L2"),
        "ms" => L.Get("ProfileMS"),
        _ => L.Get("ProfileAll"),
    };

    public static string ProfileFromLabel(string label)
    {
        foreach (var p in Profiles)
            if (ProfileLabel(p) == label) return p;
        return Profiles[0];
    }

    public static string TargetLabel(string canonical) => canonical switch
    {
        "standalone" => L.Get("TargetStandalone"),
        "both" => L.Get("TargetBoth"),
        _ => L.Get("TargetEnterprise"),
    };

    public static string TargetFromLabel(string label)
    {
        foreach (var t in Targets)
            if (TargetLabel(t) == label) return t;
        return Targets[0];
    }

    /// <summary>Localized display label for a rule target key (both/standalone/enterprise).</summary>
    public static string ZielLabel(string key) => (key ?? "").Trim().ToLowerInvariant() switch
    {
        "standalone" => L.Get("TargetStandalone"),
        "enterprise" => L.Get("TargetEnterprise"),
        _ => L.Get("TargetBoth"),
    };

    public static string SortLabel(string canonical) => canonical switch
    {
        "status" => L.Get("SortStatus"),
        "title" => L.Get("SortTitle"),
        "check-id" => L.Get("SortId"),
        _ => L.Get("SortSeverity"),
    };

    public static string SortFromLabel(string label)
    {
        foreach (var s in SortOrders)
            if (SortLabel(s) == label) return s;
        return SortOrders[0];
    }

    public static string SeverityLabel(WinHardeningAudit.Core.Models.Severity s) => s switch
    {
        WinHardeningAudit.Core.Models.Severity.Critical => L.Get("SevCritical"),
        WinHardeningAudit.Core.Models.Severity.High => L.Get("SevHigh"),
        WinHardeningAudit.Core.Models.Severity.Medium => L.Get("SevMedium"),
        WinHardeningAudit.Core.Models.Severity.Low => L.Get("SevLow"),
        _ => L.Get("SevInfo"),
    };

    public static string StatusLabel(WinHardeningAudit.Core.Models.CheckStatus s) => s switch
    {
        WinHardeningAudit.Core.Models.CheckStatus.Passed => L.Get("StatusPassed"),
        WinHardeningAudit.Core.Models.CheckStatus.Failed => L.Get("StatusFailed"),
        WinHardeningAudit.Core.Models.CheckStatus.Manual => L.Get("StatusManual"),
        WinHardeningAudit.Core.Models.CheckStatus.NotApplicable => L.Get("StatusNA"),
        WinHardeningAudit.Core.Models.CheckStatus.Warning => L.Get("StatusWarning"),
        _ => L.Get("StatusError"),
    };

    public static string ManualKindLabel(string kind) => kind switch
    {
        "discretion" => L.Get("ManualKindDiscretion"),
        "admin-environment" => L.Get("ManualKindAdmin"),
        "policy-missing" => L.Get("ManualKindPolicy"),
        _ => kind,
    };

    public ScanReport? Report { get; private set; }
    public bool IsScanning { get; private set; }
    public int RuleCount { get; private set; }
    public int L2RuleCount { get; private set; }

    private string _profile = "l1";
    public string Profile
    {
        get => _profile;
        set { if (_profile != value) { _profile = value; Changed?.Invoke(this, EventArgs.Empty); } }
    }

    private string _target = "standalone";
    public string Target
    {
        get => _target;
        set { if (_target != value) { _target = value; Changed?.Invoke(this, EventArgs.Empty); } }
    }

    private MachineContext? _machine;
    public string MachineInfo => Machine?.Display ?? Environment.OSVersion.VersionString;
    public bool IsDomainJoined => Machine?.DomainJoined ?? false;

    public MachineContext Machine => _machine ??= MachineContext.Detect();

    public sealed record MachineContext(bool DomainJoined, string DomainOrWorkgroup, string Edition, string[] DomainGpos)
    {
        public string Display => $"{Edition} Â· {(DomainJoined ? L.F("MachineDomain", DomainOrWorkgroup) : L.Get("MachineStandalone"))}" +
            (DomainGpos.Length > 0 ? $" Â· {L.F("MachineGpos", DomainGpos.Length)}" : "");
        public static MachineContext Detect()
        {
            bool joined = false;
            string name = "";
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT PartOfDomain, Domain, Workgroup FROM Win32_ComputerSystem");
                foreach (System.Management.ManagementObject mo in searcher.Get().Cast<System.Management.ManagementObject>())
                {
                    joined = Convert.ToBoolean(mo["PartOfDomain"] ?? false);
                    name = (mo[joined ? "Domain" : "Workgroup"] as string) ?? "";
                    break;
                }
            }
            catch { }
            return new MachineContext(joined, name, DetectEdition(), DetectDomainGpos());
        }

        private static string[] DetectDomainGpos()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State\\Machine\\GPO-List", false);
                if (key is null) return [];
                return key.GetSubKeyNames()
                    .Select(n => key.OpenSubKey(n, false)?.GetValue("DisplayName") as string)
                    .Where(d => !string.IsNullOrWhiteSpace(d) && d != "Local Group Policy")
                    .Cast<string>()
                    .ToArray();
            }
            catch { return []; }
        }

        private static string DetectEdition()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT Caption FROM Win32_OperatingSystem");
                foreach (System.Management.ManagementObject mo in searcher.Get().Cast<System.Management.ManagementObject>())
                    return (mo["Caption"] as string ?? "").Replace("Microsoft ", "").Trim();
            }
            catch { }
            return Environment.OSVersion.VersionString;
        }
    }

    private ScanService()
    {
        if (IsDomainJoined) _target = "both";
    }

    public bool ShowL2Banner => _profile == "l1l2";

    public event EventHandler? Changed;

    public string RulesDir
    {
        get
        {
            var candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "Rules"),
                Path.Combine(AppContext.BaseDirectory, "src", "WinHardeningAudit.Core", "Rules"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.Core", "Rules")),
            };
            foreach (var c in candidates)
                if (Directory.Exists(c) && Directory.EnumerateFiles(c, "*.json").Any())
                    return c;
            return candidates[0];
        }
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        if (IsScanning) return;
        IsScanning = true;
        Changed?.Invoke(this, EventArgs.Empty);
        try
        {
            var rules = await Task.Run(() => CheckRunner.LoadRulesFromDirectory(RulesDir), ct);
            RuleCount = rules.Count;
            L2RuleCount = rules.Count(r => r.Profil == "L2");
            var runner = new CheckRunner();
            Report = await runner.RunAsync(rules, ct);
        }
        finally
        {
            IsScanning = false;
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    private bool ProfileMatches(RuleDefinition r) => _profile switch
    {
        "l1" => r.Profil == "L1",
        "l1l2" => r.Profil is "L1" or "L2",
        "ms" => r.Profil == "MS",
        _ => true,
    };

    /// <summary>Applies the one-click fix for a rule, then re-checks just that rule.</summary>
    /// <returns>Apply outcome; on success the report already contains the fresh result.</returns>
    public async Task<RemediationOutcome> ApplyFixAsync(string ruleId, CancellationToken ct = default)
    {
        if (Report is null) throw new InvalidOperationException(L.Get("ErrNoReport"));
        var current = Report.Results.FirstOrDefault(r => r.Rule.Id == ruleId)
            ?? throw new InvalidOperationException($"Unknown rule: {ruleId}");
        var outcome = await RemediationRunner.ApplyAsync(current.Rule, ct);
        if (!outcome.Success) return outcome;
        var fresh = await new CheckRunner().RunAsync(new[] { current.Rule }, ct);
        var updated = fresh.Results.FirstOrDefault();
        if (updated is not null)
        {
            var list = Report.Results.ToList();
            var idx = list.FindIndex(r => r.Rule.Id == ruleId);
            if (idx >= 0) list[idx] = updated;
            var passed = list.Count(r => r.Status == CheckStatus.Passed);
            var failed = list.Count(r => r.Status == CheckStatus.Failed);
            Report = new ScanReport
            {
                Timestamp = Report.Timestamp,
                MachineName = Report.MachineName,
                OsVersion = Report.OsVersion,
                IsElevated = CheckRunner.IsElevated(),
                Results = list
                    .OrderByDescending(r => r.Rule.Severity)
                    .ThenBy(r => r.Status == CheckStatus.Passed ? 1 : 0)
                    .ToList(),
                Summary = new ScanSummary
                {
                    Total = list.Count,
                    Passed = passed,
                    Failed = failed,
                    Manual = list.Count(r => r.Status is CheckStatus.Manual or CheckStatus.NotApplicable or CheckStatus.Warning),
                    Errors = list.Count(r => r.Status == CheckStatus.Error),
                    CriticalOpen = list.Count(r => r.Rule.Severity == Severity.Critical && r.Status == CheckStatus.Failed),
                    HighOpen = list.Count(r => r.Rule.Severity == Severity.High && r.Status == CheckStatus.Failed),
                    ScorePercent = Math.Round(100.0 * passed / Math.Max(1, passed + failed), 1),
                },
                FilterNote = Report.FilterNote,
            };
            Changed?.Invoke(this, EventArgs.Empty);
        }
        return outcome with { RequiresReboot = outcome.RequiresReboot || current.Rule.Remediation?.RequiresReboot == true };
    }

    private bool TargetMatches(RuleDefinition r) => _target switch
    {
        "standalone" => (r.Ziel ?? "both").Trim().ToLowerInvariant() is "both" or "standalone",
        "enterprise" => (r.Ziel ?? "both").Trim().ToLowerInvariant() is "both" or "enterprise",
        _ => true,
    };

    public IEnumerable<CheckResult> VisibleResults()
        => (Report?.Results ?? Enumerable.Empty<CheckResult>())
            .Where(r => ProfileMatches(r.Rule) && TargetMatches(r.Rule));

    public static readonly string[] SortOrders = { "severity", "status", "title", "check-id" };

    public IEnumerable<CheckResult> ForCategory(string category, bool onlyOpen = false, bool onlySevere = false, string? search = null, string sort = "severity")
    {
        var q = VisibleResults().Where(r => r.Rule.Category == category);
        if (onlyOpen) q = q.Where(r => r.Status == CheckStatus.Failed);
        if (onlySevere) q = q.Where(r => r.Rule.Severity is Severity.Critical or Severity.High);
        if (!string.IsNullOrWhiteSpace(search))
            q = q.Where(r => (r.Rule.Title + " " + r.Rule.Id + " " + r.Rule.Description).Contains(search, StringComparison.OrdinalIgnoreCase));
        return sort switch
        {
            "status" => q.OrderBy(StatusRank).ThenByDescending(r => r.Rule.Severity),
            "title" => q.OrderBy(r => r.Rule.Title),
            "check-id" => q.OrderBy(r => r.Rule.Id),
            _ => q.OrderByDescending(r => r.Rule.Severity).ThenBy(r => r.Status == CheckStatus.Passed ? 1 : 0),
        };
    }

    private static int StatusRank(CheckResult r) => r.Status switch
    {
        CheckStatus.Failed => 0,
        CheckStatus.Error => 1,
        CheckStatus.Warning => 2,
        CheckStatus.Manual => 3,
        CheckStatus.NotApplicable => 4,
        _ => 5,
    };

    public IEnumerable<CheckResult> SearchAll(string query, int max = 30)
    {
        if (string.IsNullOrWhiteSpace(query) || query.Trim().Length < 2) return Enumerable.Empty<CheckResult>();
        var q = query.Trim();
        return VisibleResults()
            .Where(r => (r.Rule.Title + " " + r.Rule.Id + " " + r.Rule.Description + " " + r.Rule.Category + " " + r.Rule.FixHint + " " + (r.ActualValue ?? "")).Contains(q, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(r => r.Rule.Severity)
            .ThenBy(r => r.Status == CheckStatus.Passed ? 1 : 0)
            .Take(Math.Max(1, max));
    }

    public IEnumerable<CheckResult> TopRisks(int n = 5)
        => VisibleResults()
            .Where(r => r.Status == CheckStatus.Failed)
            .OrderByDescending(r => r.Rule.Severity).Take(n);

    public (int total, int passed, int failed) CategoryCounts(string category)
    {
        var list = VisibleResults().Where(r => r.Rule.Category == category).ToList();
        return (list.Count, list.Count(r => r.Status == CheckStatus.Passed), list.Count(r => r.Status == CheckStatus.Failed));
    }

    public (int total, int passed, int failed, int crit, int high) FilteredSummary()
    {
        var list = VisibleResults().ToList();
        return (list.Count, list.Count(r => r.Status == CheckStatus.Passed), list.Count(r => r.Status == CheckStatus.Failed),
            list.Count(r => r.Rule.Severity == Severity.Critical && r.Status == CheckStatus.Failed),
            list.Count(r => r.Rule.Severity == Severity.High && r.Status == CheckStatus.Failed));
    }

    public double FilteredScore()
    {
        var (total, passed, failed, _, _) = FilteredSummary();
        var denom = Math.Max(1, passed + failed);
        return Math.Round(100.0 * passed / denom, 1);
    }

    private ScanReport FilteredReport() => BuildReport(VisibleResults(), L.F("FilterNote", ProfileLabel(_profile), TargetLabel(_target)));

    private ScanReport FullReport()
    {
        if (Report is null) throw new InvalidOperationException(L.Get("ErrNoReport"));
        return BuildReport(Report.Results, L.Get("FilterNoteFull"));
    }

    private ScanReport BuildReport(IEnumerable<CheckResult> source, string note)
    {
        if (Report is null) throw new InvalidOperationException(L.Get("ErrNoReport"));
        var list = source.OrderByDescending(r => r.Rule.Severity).ToList();
        var passed = list.Count(r => r.Status == CheckStatus.Passed);
        var failed = list.Count(r => r.Status == CheckStatus.Failed);
        return new ScanReport
        {
            Timestamp = Report.Timestamp,
            MachineName = Report.MachineName,
            OsVersion = Report.OsVersion,
            IsElevated = Report.IsElevated,
            Results = list,
            Summary = new ScanSummary
            {
                Total = list.Count,
                Passed = passed,
                Failed = failed,
                Manual = list.Count(r => r.Status is CheckStatus.Manual or CheckStatus.NotApplicable or CheckStatus.Warning),
                Errors = list.Count(r => r.Status == CheckStatus.Error),
                CriticalOpen = list.Count(r => r.Rule.Severity == Severity.Critical && r.Status == CheckStatus.Failed),
                HighOpen = list.Count(r => r.Rule.Severity == Severity.High && r.Status == CheckStatus.Failed),
                ScorePercent = Math.Round(100.0 * passed / Math.Max(1, passed + failed), 1),
            },
            FilterNote = note,
        };
    }

    public string ExportFullHtml()
    {
        var dir = ExportDir();
        var path = Path.Combine(dir, $"HardeningAudit-VOLL-{DateTime.Now:yyyyMMdd-HHmm}.html");
        File.WriteAllText(path, ReportExporter.ToHtml(FullReport(), CurrentReportTexts()));
        return path;
    }

    public string ExportJson()
    {
        var dir = ExportDir();
        var path = Path.Combine(dir, $"HardeningAudit-{DateTime.Now:yyyyMMdd-HHmm}.json");
        File.WriteAllText(path, ReportExporter.ToJson(FilteredReport()));
        return path;
    }

    public string ExportHtml()
    {
        var dir = ExportDir();
        var path = Path.Combine(dir, $"HardeningAudit-{DateTime.Now:yyyyMMdd-HHmm}.html");
        File.WriteAllText(path, ReportExporter.ToHtml(FilteredReport(), CurrentReportTexts()));
        return path;
    }

    public string ExportCsv()
    {
        var dir = ExportDir();
        var path = Path.Combine(dir, $"HardeningAudit-{DateTime.Now:yyyyMMdd-HHmm}.csv");
        File.WriteAllText(path, ReportExporter.ToCsv(FilteredReport(), CurrentReportTexts()), System.Text.Encoding.UTF8);
        return path;
    }

    public static ReportTexts CurrentReportTexts() => new()
    {
        Title = L.Get("ReportTitle"),
        Score = L.Get("RptScore"),
        Passed = L.Get("RptPassed"),
        Open = L.Get("RptOpen"),
        Manual = L.Get("RptManual"),
        CriticalOpen = L.Get("RptCriticalOpen"),
        HighOpen = L.Get("RptHighOpen"),
        Admin = L.Get("RptAdmin"),
        Yes = L.Get("YesNoTrue"),
        No = L.Get("YesNoFalse"),
        ColStatus = L.Get("SortStatus"),
        ColSeverity = L.Get("SortSeverity"),
        ColCheck = L.Get("ColCheck"),
        ColActual = L.Get("DetailActual"),
        ColExpected = L.Get("DetailExpected"),
        ColSource = L.Get("ColSource"),
        ColRecommendation = L.Get("DetailFix"),
        SevCritical = L.Get("SevCritical"),
        SevHigh = L.Get("SevHigh"),
        SevMedium = L.Get("SevMedium"),
        StatusPassed = L.Get("StatusPassed"),
        StatusFailed = L.Get("StatusFailed"),
        StatusManual = L.Get("StatusManual"),
        StatusManualKind = L.Get("StatusManualKind"),
        StatusNA = L.Get("StatusNA"),
        StatusWarning = L.Get("StatusWarning"),
        StatusError = L.Get("StatusError"),
        KindDiscretion = L.Get("ManualKindDiscretion"),
        KindAdmin = L.Get("ManualKindAdmin"),
        KindPolicy = L.Get("ManualKindPolicy"),
        MetaChapter = L.Get("MetaChapter"),
        MetaProfile = L.Get("MetaProfile"),
        MetaTarget = L.Get("MetaTarget"),
        MetaValidFrom = L.Get("MetaValidFrom"),
        NotePrefix = L.Get("Note26H2Prefix"),
        CsvTitle = L.Get("SortTitle"),
        CsvCategory = L.Get("CsvCategory"),
        CsvManualReason = L.Get("CsvManualReason"),
        CsvMessage = L.Get("CsvMessage"),
        CsvNote = L.Get("CsvNote"),
        CategoryName = CategoryLabel,
        TargetName = ZielLabel,
    };

    private static string ExportDir()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "HardeningAudit");
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>Report folder (shown on the Settings page).</summary>
    public static string ExportFolder => ExportDir();
}

