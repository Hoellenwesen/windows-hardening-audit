using System.Globalization;
using System.Text;
using System.Text.Json;
using WinHardeningAudit.Core.Models;

namespace WinHardeningAudit.Core.Export;

/// <summary>
/// All display strings for HTML/CSV reports. <see cref="English"/> is the default;
/// the WinUI app builds a localized instance from .resw via ScanService.
/// </summary>
public sealed record ReportTexts
{
    public string Title { get; init; } = "Windows 11 Hardening Audit";
    public string DocTitle { get; init; } = "Hardening audit";
    public string Score { get; init; } = "Score";
    public string Passed { get; init; } = "Passed";
    public string Open { get; init; } = "Open";
    public string Manual { get; init; } = "Manual";
    public string CriticalOpen { get; init; } = "Critical open";
    public string HighOpen { get; init; } = "High open";
    public string Admin { get; init; } = "Admin";
    public string Yes { get; init; } = "yes";
    public string No { get; init; } = "no";
    public string ColStatus { get; init; } = "Status";
    public string ColSeverity { get; init; } = "Severity";
    public string ColCheck { get; init; } = "Check";
    public string ColActual { get; init; } = "Actual";
    public string ColExpected { get; init; } = "Expected";
    public string ColSource { get; init; } = "Source";
    public string ColRecommendation { get; init; } = "Recommendation";
    public string SevCritical { get; init; } = "Critical";
    public string SevHigh { get; init; } = "High";
    public string SevMedium { get; init; } = "Medium";
    public string StatusPassed { get; init; } = "Passed";
    public string StatusFailed { get; init; } = "Not met";
    public string StatusManual { get; init; } = "Manual review";
    public string StatusManualKind { get; init; } = "Manual: {0}";
    public string StatusNA { get; init; } = "N/A";
    public string StatusWarning { get; init; } = "Warning";
    public string StatusError { get; init; } = "Error";
    public string KindDiscretion { get; init; } = "Judgment";
    public string KindAdmin { get; init; } = "Admin/environment";
    public string KindPolicy { get; init; } = "Policy missing";
    public string MetaChapter { get; init; } = "Chapter";
    public string MetaProfile { get; init; } = "Profile";
    public string MetaTarget { get; init; } = "Target";
    public string MetaValidFrom { get; init; } = "Applies since";
    public string NotePrefix { get; init; } = "Note 26H2: ";
    public string CsvTitle { get; init; } = "Title";
    public string CsvCategory { get; init; } = "Category";
    public string CsvManualReason { get; init; } = "Manual reason";
    public string CsvMessage { get; init; } = "Message";
    public string CsvNote { get; init; } = "Note 26H2";
    public Func<string, string> CategoryName { get; init; } = EnglishCategoryName;
    public Func<string, string> TargetName { get; init; } = EnglishTargetName;

    public string KindLabel(string kind) => kind switch
    {
        "discretion" => KindDiscretion,
        "admin-environment" => KindAdmin,
        "policy-missing" => KindPolicy,
        _ => kind,
    };

    public static string EnglishCategoryName(string key) => key switch
    {
        "accounts-uac" => "Accounts & UAC",
        "defender-malware" => "Defender & malware protection",
        "bitlocker-encryption" => "BitLocker & encryption",
        "firewall-network" => "Firewall & network",
        "secureboot-vbs" => "Secure Boot & virtualization",
        "updates-maintenance" => "Updates & maintenance",
        "audit-logging" => "Audit & logging",
        "system-hardening" => "System hardening",
        "browser-edge" => "Browser & Edge",
        "user-rights" => "User rights",
        "services" => "Services",
        _ => key,
    };

    public static string EnglishTargetName(string key) => (key ?? "").Trim().ToLowerInvariant() switch
    {
        "standalone" => "Standalone",
        "enterprise" => "Enterprise",
        _ => "Both",
    };

    public static ReportTexts English { get; } = new();
}

public static class ReportExporter
{
    public static string ToJson(ScanReport report)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        options.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        return JsonSerializer.Serialize(report, options);
    }

    public static string ToHtml(ScanReport report, ReportTexts? texts = null)
    {
        var t = texts ?? ReportTexts.English;
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>");
        sb.Append("<title>");
        sb.Append(E(t.DocTitle));
        sb.Append(' ');
        sb.Append(report.Timestamp.ToString("g", CultureInfo.CurrentCulture));
        sb.Append("</title><style>");
        sb.Append("body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#1b1b1b;background:#f7f7f7}");
        sb.Append(".card{background:#fff;border-radius:12px;padding:16px 20px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.08)}");
        sb.Append("table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid #eee}");
        sb.Append(".pass{color:#107c10;font-weight:700}.fail{color:#c42b1c;font-weight:700}.man{color:#666}");
        sb.Append(".badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700}");
        sb.Append(".crit{background:#fde7e9;color:#c42b1c}.high{background:#fef0cd;color:#8a5a00}.med{background:#e5f0ff;color:#0f4cbd}.low{background:#eee}");
        sb.Append("h2{margin-top:32px}</style></head><body>");
        sb.Append($"<div class='card'><h1>{E(t.Title)}</h1><p>{E(report.MachineName)} · {E(report.OsVersion)} · {E(t.Admin)}: {(report.IsElevated ? E(t.Yes) : E(t.No))} · {report.Timestamp.ToString("g", CultureInfo.CurrentCulture)}");
        if (!string.IsNullOrWhiteSpace(report.FilterNote)) sb.Append($" · {E(report.FilterNote)}");
        sb.Append("</p>");
        sb.Append($"<p><strong>{E(t.Score)}: {report.Summary.ScorePercent}%</strong> · {E(t.Passed)}: {report.Summary.Passed} · {E(t.Open)}: {report.Summary.Failed} · {E(t.Manual)}: {report.Summary.Manual} · {E(t.CriticalOpen)}: {report.Summary.CriticalOpen} · {E(t.HighOpen)}: {report.Summary.HighOpen}</p></div>");

        foreach (var g in report.Results.GroupBy(r => r.Rule.Category).OrderBy(g => t.CategoryName(g.Key)))
        {
            sb.Append($"<h2>{E(t.CategoryName(g.Key))} ({g.Count()})</h2><div class='card'><table>");
            sb.Append($"<tr><th>{E(t.ColStatus)}</th><th>{E(t.ColSeverity)}</th><th>{E(t.ColCheck)}</th><th>{E(t.ColActual)}</th><th>{E(t.ColExpected)}</th><th>{E(t.ColSource)}</th><th>{E(t.ColRecommendation)}</th></tr>");
            foreach (var r in g.OrderByDescending(x => x.Rule.Severity))
            {
                var cls = r.Status == CheckStatus.Passed ? "pass" : r.Status == CheckStatus.Failed ? "fail" : "man";
                var sev = r.Rule.Severity switch
                {
                    Severity.Critical => $"<span class='badge crit'>{E(t.SevCritical)}</span>",
                    Severity.High => $"<span class='badge high'>{E(t.SevHigh)}</span>",
                    Severity.Medium => $"<span class='badge med'>{E(t.SevMedium)}</span>",
                    _ => "<span class='badge low'>" + E(r.Rule.Severity.ToString()) + "</span>"
                };
                var status = r.Status == CheckStatus.Manual && !string.IsNullOrWhiteSpace(r.ManualKind)
                    ? string.Format(t.StatusManualKind, E(t.KindLabel(r.ManualKind)))
                    : StatusText(t, r.Status);
                var details = string.Join(" · ", new[]
                {
                    string.IsNullOrWhiteSpace(r.Rule.Kapitel) ? "" : $"{E(t.MetaChapter)}: {r.Rule.Kapitel}",
                    $"{E(t.MetaProfile)}: {r.Rule.Profil}", $"{E(t.MetaTarget)}: {t.TargetName(r.Rule.Ziel)}", $"{E(t.MetaValidFrom)}: {r.Rule.GiltAb}",
                }.Where(s => !string.IsNullOrEmpty(s)));
                var notiz = string.IsNullOrWhiteSpace(r.Rule.Notiz26H2) ? "" : $"<br><small><i>{E(t.NotePrefix)}{E(r.Rule.Notiz26H2)}</i></small>";
                sb.Append($"<tr><td class='{cls}'>{E(status)}</td><td>{sev}</td><td><strong>{E(r.Rule.Title)}</strong><br><small>{E(r.Rule.Id)} – {E(r.Rule.Description)}</small><br><small>{E(details)}</small>{notiz}</td><td><code>{E(r.ActualValue ?? "–")}</code></td><td><code>{E(r.ExpectedValue ?? "–")}</code></td><td>{E(r.Rule.Source)} {E(r.Rule.SourceId)}</td><td>{E(r.Rule.FixHint)}</td></tr>");
            }
            sb.Append("</table></div>");
        }
        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static string StatusText(ReportTexts t, CheckStatus s) => s switch
    {
        CheckStatus.Passed => t.StatusPassed,
        CheckStatus.Failed => t.StatusFailed,
        CheckStatus.Manual => t.StatusManual,
        CheckStatus.NotApplicable => t.StatusNA,
        CheckStatus.Warning => t.StatusWarning,
        _ => t.StatusError
    };

    public static string ToCsv(ScanReport report, ReportTexts? texts = null)
    {
        var t = texts ?? ReportTexts.English;
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(";", new[]
        {
            "Id", t.CsvTitle, t.CsvCategory, t.ColStatus, t.CsvManualReason,
            t.ColSeverity, t.MetaProfile, t.MetaTarget, t.MetaChapter, t.MetaValidFrom,
            t.ColActual, t.ColExpected, t.ColSource, "SourceId",
            t.ColRecommendation, t.CsvMessage, t.CsvNote,
        }));
        foreach (var r in report.Results)
        {
            var status = r.Status == CheckStatus.Manual && !string.IsNullOrWhiteSpace(r.ManualKind)
                ? string.Format(t.StatusManualKind, t.KindLabel(r.ManualKind)) : StatusText(t, r.Status);
            sb.AppendLine(string.Join(";", new[]
            {
                r.Rule.Id, r.Rule.Title, t.CategoryName(r.Rule.Category), status, t.KindLabel(r.ManualKind),
                r.Rule.Severity.ToString(), r.Rule.Profil, t.TargetName(r.Rule.Ziel), r.Rule.Kapitel, r.Rule.GiltAb,
                r.ActualValue ?? "", r.ExpectedValue ?? "", r.Rule.Source, r.Rule.SourceId,
                r.Rule.FixHint, r.Message, r.Rule.Notiz26H2 ?? "",
            }.Select(Csv)));
        }
        return sb.ToString();
    }

    private static string Csv(string? s)
    {
        s = (s ?? "").Replace("\r", " ").Replace("\n", " ");
        return s.Contains(';') || s.Contains('"') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    private static string E(string? s) => System.Net.WebUtility.HtmlEncode(s ?? "");
}
