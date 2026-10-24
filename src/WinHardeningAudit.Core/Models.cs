namespace WinHardeningAudit.Core.Models;

public enum Severity
{
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Info = 0
}

public enum CheckStatus
{
    Passed,
    Failed,
    Warning,
    Manual,
    NotApplicable,
    Error
}

public sealed record CheckSpec
{
    public string Provider { get; init; } = "registry";
    public string Key { get; init; } = "";
    public string ValueName { get; init; } = "";
    public string Operator { get; init; } = "Equals";
    public string? Expected { get; init; }
    public string? Script { get; init; }
    public string MissingIs { get; init; } = "Failed";
}

/// <summary>A single, typed remediation step ("Beheben"). Handlers live in RemediationScript.</summary>
public sealed record RemediationAction
{
    /// <summary>registry | service | account | auditpol | eventlog | firewallProfile | smb | netaccounts | secedit</summary>
    public string Type { get; init; } = "";
    /// <summary>registry: full key path, e.g. HKLM\SOFTWARE\...</summary>
    public string? Key { get; init; }
    public string? ValueName { get; init; }
    /// <summary>registry: dword | qword | string | expandstring</summary>
    public string? ValueType { get; init; }
    public string? Value { get; init; }
    /// <summary>service/account: service or account name</summary>
    public string? Name { get; init; }
    public string? StartType { get; init; }
    /// <summary>service: also start the service after configuring it</summary>
    public bool Start { get; init; }
    /// <summary>auditpol: subcategory GUID (without braces)</summary>
    public string? Subcategory { get; init; }
    public bool? Success { get; init; }
    public bool? Failure { get; init; }
    public string? Log { get; init; }
    public long? MaxSizeBytes { get; init; }
    public string? Profile { get; init; }
    public bool? Enabled { get; init; }
    /// <summary>netaccounts: switch name without slash, e.g. maxpwage</summary>
    public string? Switch { get; init; }
}

/// <summary>Per-rule remediation metadata ("Behebung" button + manual guide).</summary>
public sealed record RemediationSpec
{
    /// <summary>auto = one-click fix available, manual = instructions only.</summary>
    public string Mode { get; init; } = "manual";
    /// <summary>low | medium | high. "high" never combines with mode=auto.</summary>
    public string Risk { get; init; } = "low";
    public bool RequiresReboot { get; init; }
    /// <summary>GUI path (secpol.msc > ...) in the rule-file language; overlays translate it.</summary>
    public string Gui { get; init; } = "";
    public List<RemediationAction> Actions { get; init; } = new();
    /// <summary>Manual instructions; only used/required for mode=manual. Auto rules derive steps from actions.</summary>
    public List<string> Steps { get; init; } = new();
}

public sealed record RuleDefinition
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    /// <summary>Language-neutral category key (e.g. "accounts-uac"); display names come from UI resources.</summary>
    public string Category { get; init; } = "";
    public string Source { get; init; } = "";
    public string SourceId { get; init; } = "";
    public Severity Severity { get; init; } = Severity.Medium;
    public CheckSpec Check { get; init; } = new();
    public string FixHint { get; init; } = "";
    public RemediationSpec? Remediation { get; init; }
    public string Profil { get; init; } = "L1";
    public string Kapitel { get; init; } = "";
    public string GiltAb { get; init; } = "24H2";
    public string? Notiz26H2 { get; init; }
    /// <summary>Language-neutral target key: "both", "standalone" or "enterprise".</summary>
    public string Ziel { get; init; } = "both";
}

public sealed record CheckResult
{
    public RuleDefinition Rule { get; init; } = new();
    public CheckStatus Status { get; init; }
    public string? ActualValue { get; init; }
    public string? ExpectedValue { get; init; }
    public string Message { get; init; } = "";
    public long DurationMs { get; init; }
    public string ManualKind { get; init; } = "";
}

public sealed record ScanSummary
{
    public int Total { get; init; }
    public int Passed { get; init; }
    public int Failed { get; init; }
    public int Manual { get; init; }
    public int Errors { get; init; }
    public int CriticalOpen { get; init; }
    public int HighOpen { get; init; }
    public double ScorePercent { get; init; }
}

public sealed record ScanReport
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public string MachineName { get; init; } = Environment.MachineName;
    public string OsVersion { get; init; } = Environment.OSVersion.VersionString;
    public bool IsElevated { get; init; }
    public List<CheckResult> Results { get; init; } = new();
    public ScanSummary Summary { get; init; } = new();
    public string FilterNote { get; init; } = "";
}
