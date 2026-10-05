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
