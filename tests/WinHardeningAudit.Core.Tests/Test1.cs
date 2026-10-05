using System.Text.Json;
using WinHardeningAudit.Core.Engine;
using WinHardeningAudit.Core.Export;
using WinHardeningAudit.Core.Models;

namespace WinHardeningAudit.Core.Tests;

[TestClass]
public sealed class CompareTests
{
    [TestMethod]
    [DataRow("1", "1", "Equals", true)]
    [DataRow("True", "true", "Equals", true)]
    [DataRow("On", "Off", "Equals", false)]
    [DataRow("  5  ", "5", "Equals", true)]
    [DataRow("Success and Failure", "Success", "Contains", true)]
    [DataRow("3", "7", "LessOrEqual", true)]
    [DataRow("10", "7", "LessOrEqual", false)]
    [DataRow("1", "1", "GreaterOrEqual", true)]
    public void Compare_Works(string actual, string expected, string op, bool want)
    {
        Assert.AreEqual(want, RegistryProvider.Compare(actual, expected, op));
    }

    [TestMethod]
    public async Task MissingKey_Respects_MissingIs()
    {
        var p = new RegistryProvider();
        foreach (var (missingIs, want) in new[] { ("Failed", CheckStatus.Failed), ("Manual", CheckStatus.Manual), ("Passed", CheckStatus.Passed) })
        {
            var rule = new RuleDefinition
            {
                Id = "T",
                Check = new CheckSpec { Provider = "registry", Key = "HKLM\\SOFTWARE\\Does\\Not\\Exist\\XYZ", ValueName = "Nope", Operator = "Equals", Expected = "1", MissingIs = missingIs }
            };
            var r = await p.EvaluateAsync(rule, CancellationToken.None);
            Assert.AreEqual(want, r.Status);
        }
    }

    [TestMethod]
    public async Task ManualProvider_Always_Manual()
    {
        var p = new ManualProvider();
        var r = await p.EvaluateAsync(new RuleDefinition(), CancellationToken.None);
        Assert.AreEqual(CheckStatus.Manual, r.Status);
    }

    [TestMethod]
    public void All_Rule_Files_Are_Valid_And_Unique()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules");
        if (!Directory.Exists(dir))
        {
            // Fallback: Quellverzeichnis (wenn Tests nicht kopieren)
            dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.Core", "Rules"));
        }
        var rules = CheckRunner.LoadRulesFromDirectory(dir);
        Assert.IsTrue(rules.Count >= 40, $"Erwartet >= 40 Regeln, gefunden: {rules.Count}");
        var dupes = rules.GroupBy(r => r.Id).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.AreEqual(0, dupes.Count, "Doppelte IDs: " + string.Join(",", dupes));
        foreach (var r in rules)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(r.Id), "Regel ohne ID");
            Assert.IsFalse(string.IsNullOrWhiteSpace(r.Category), $"Regel {r.Id} ohne Kategorie");
            Assert.IsFalse(string.IsNullOrWhiteSpace(r.Title), $"Regel {r.Id} ohne Titel");
        }
    }

    [TestMethod]
    public async Task Runner_SmokeTest_With_Fake_Rules()
    {
        var rules = new[]
        {
            new RuleDefinition { Id = "S1", Title = "t", Category = "Kat", Severity = Severity.High, Check = new CheckSpec { Provider = "manual" } },
            new RuleDefinition { Id = "S2", Title = "t", Category = "Kat", Severity = Severity.Critical, Check = new CheckSpec { Provider = "registry", Key = "HKLM\\SOFTWARE\\Does\\Not\\Exist", ValueName = "X", Operator = "Equals", Expected = "1", MissingIs = "Failed" } },
        };
        var report = await new CheckRunner().RunAsync(rules);
        Assert.AreEqual(2, report.Summary.Total);
        Assert.AreEqual(1, report.Summary.Manual);
        Assert.AreEqual(1, report.Summary.Failed);
        Assert.AreEqual(1, report.Summary.CriticalOpen);
    }
}

[TestClass]
public sealed class SeceditTests
{
    [TestMethod]
    public void ParseInf_Reads_Sections()
    {
        var inf = "[System Access]\nMinimumPasswordLength = 14\nPasswordComplexity = 1\n[Privilege Rights]\nSeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11\n";
        var sections = SeceditProvider.ParseInf(inf);
        Assert.AreEqual("14", sections["System Access"]["MinimumPasswordLength"]);
        Assert.AreEqual("*S-1-5-32-544,*S-1-5-11", sections["Privilege Rights"]["SeNetworkLogonRight"]);
    }

    [TestMethod]
    [DataRow("*S-1-5-32-544,*S-1-5-11", "S-1-5-11,S-1-5-32-544", "Equals", true)]
    [DataRow("*S-1-5-32-544", "S-1-5-32-544,S-1-5-11", "Equals", false)]
    [DataRow("*S-1-5-32-544,*S-1-5-11", "S-1-5-11", "Contains", true)]
    [DataRow("*S-1-5-32-544,*S-1-5-11,*S-1-5-32-545", "S-1-5-11,S-1-5-32-544", "ContainsAll", true)]
    [DataRow("60", "60", "LessOrEqual", true)]
    [DataRow("90", "60", "LessOrEqual", false)]
    public void CompareSecedit_Works(string actual, string expected, string op, bool want)
    {
        Assert.AreEqual(want, SeceditProvider.CompareSecedit(actual, expected, op));
    }

    [TestMethod]
    public void TranslateSids_Maps_Known()
    {
        var t = SeceditProvider.TranslateSids("*S-1-5-32-544,*S-1-5-11");
        Assert.IsTrue(t.Contains("Administrators") && t.Contains("Authenticated Users"));
    }

    [TestMethod]
    public void All_Rules_Pass_Validation()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules");
        if (!Directory.Exists(dir))
            dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.Core", "Rules"));
        var rules = CheckRunner.LoadRulesFromDirectory(dir);
        var problems = CheckRunner.ValidateRules(rules);
        Assert.AreEqual(0, problems.Count, "Validierungsfehler:\n" + string.Join("\n", problems.Take(20)));
    }

    [TestMethod]
    public void ValidateRules_Catches_Bad_Values()
    {
        RuleDefinition R(string id, string provider, string op, string cat = "accounts-uac") => new()
        {
            Id = id, Title = "t", Category = cat, Severity = Severity.High,
            Check = new CheckSpec { Provider = provider, Key = "HKLM\\SOFTWARE\\X", ValueName = "V", Operator = op, Expected = "1", Script = provider == "script" ? "x" : null }
        };
        var bad = new[]
        {
            R("B1", "nonsense", "Equals"),
            R("B2", "registry", "FuzzyMatch"),
            R("B3", "registry", "Equals", "Unbekannte Kat"),
            R("B4", "secedit", "Equals"),
        };
        var problems = CheckRunner.ValidateRules(bad);
        Assert.IsTrue(problems.Any(p => p.Contains("B1")), "Provider-Fehler B1 nicht erkannt: " + string.Join("; ", problems));
        Assert.IsTrue(problems.Any(p => p.Contains("B2")), "Operator-Fehler B2 nicht erkannt");
        Assert.IsTrue(problems.Any(p => p.Contains("B3")), "Kategorie-Fehler B3 nicht erkannt");
        Assert.IsTrue(problems.Any(p => p.Contains("B4")), "secedit-Key-Fehler B4 nicht erkannt");
        var good = new[] { R("G1", "registry", "Equals"), R("G2", "manual", "Equals") };
        Assert.AreEqual(0, CheckRunner.ValidateRules(good).Count);
    }

    [TestMethod]
    public async Task Runner_Cancelled_Returns_Empty_Report()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var rules = new[] { new RuleDefinition { Id = "C1", Title = "t", Category = "Kat", Check = new CheckSpec { Provider = "manual" } } };
        var report = await new CheckRunner().RunAsync(rules, cts.Token);
        Assert.AreEqual(0, report.Summary.Total);
    }

    [TestMethod]
    public async Task Script_NA_Output_Maps_To_NotApplicable()
    {
        var rule = new RuleDefinition
        {
            Id = "NA1", Title = "t", Category = "Kat",
            Check = new CheckSpec { Provider = "script", Operator = "Equals", Expected = "True", Script = "'N/A'" }
        };
        var report = await new CheckRunner().RunAsync(new[] { rule });
        Assert.AreEqual(CheckStatus.NotApplicable, report.Results[0].Status);
    }

    [TestMethod]
    public async Task Manual_Rules_Carry_ManualKind()
    {
        var rule = new RuleDefinition
        {
            Id = "M1", Title = "t", Category = "Kat",
            Check = new CheckSpec { Provider = "manual" }
        };
        var report = await new CheckRunner().RunAsync(new[] { rule });
        Assert.AreEqual(CheckStatus.Manual, report.Results[0].Status);
        Assert.AreEqual("discretion", report.Results[0].ManualKind);
    }

    [TestMethod]
    public void Exporter_Csv_Contains_All_Columns()
    {
        var report = new ScanReport
        {
            MachineName = "PC",
            Results = new List<CheckResult>
            {
                new() { Rule = new RuleDefinition { Id = "X1", Title = "Titel", Category = "accounts-uac", Severity = Severity.High, Profil = "L1", Ziel = "both", Kapitel = "Kap", GiltAb = "24H2", Notiz26H2 = "Notiz", FixHint = "Fix", Source = "Q", SourceId = "1" }, Status = CheckStatus.Failed, ActualValue = "0", ExpectedValue = "1", Message = "Msg" },
                new() { Rule = new RuleDefinition { Id = "X2", Title = "T2", Category = "accounts-uac", Severity = Severity.Low }, Status = CheckStatus.Manual, ManualKind = "discretion" },
            },
            Summary = new ScanSummary { Total = 2, Passed = 0, Failed = 1, Manual = 1 },
        };
        var csv = ReportExporter.ToCsv(report);
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.AreEqual(3, lines.Length);
        Assert.IsTrue(lines[0].StartsWith("Id;Title;Category;Status;"));
        Assert.IsTrue(lines[1].Contains("Not met") && lines[1].Contains("X1"));
        Assert.IsTrue(lines[2].Contains("Manual: Judgment"));
        Assert.IsTrue(lines[1].Contains("Both"), "target key 'both' should render as Both");
    }

    [TestMethod]
    public void Exporter_German_Texts_Render()
    {
        var de = new ReportTexts
        {
            StatusFailed = "Nicht erfüllt",
            StatusManualKind = "Manuell: {0}",
            KindDiscretion = "Ermessen",
            MetaChapter = "Kapitel",
            NotePrefix = "Hinweis 26H2: ",
            CsvTitle = "Titel",
            CsvCategory = "Rubrik",
            CategoryName = _ => "Konten & UAC",
        };
        var report = new ScanReport
        {
            MachineName = "PC",
            Results = new List<CheckResult>
            {
                new() { Rule = new RuleDefinition { Id = "X1", Title = "Titel", Category = "accounts-uac", Severity = Severity.High, Profil = "L1", Ziel = "both", Kapitel = "Kap", GiltAb = "24H2", Notiz26H2 = "Notiz", FixHint = "Fix", Source = "Q", SourceId = "1" }, Status = CheckStatus.Failed, ActualValue = "0", ExpectedValue = "1", Message = "Msg" },
                new() { Rule = new RuleDefinition { Id = "X2", Title = "T2", Category = "accounts-uac", Severity = Severity.Low }, Status = CheckStatus.Manual, ManualKind = "discretion" },
            },
            Summary = new ScanSummary { Total = 2, Passed = 0, Failed = 1, Manual = 1 },
        };
        var csv = ReportExporter.ToCsv(report, de);
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.IsTrue(lines[0].StartsWith("Id;Titel;Rubrik;Status;"));
        Assert.IsTrue(lines[1].Contains("Nicht erfüllt") && lines[1].Contains("X1"));
        Assert.IsTrue(lines[2].Contains("Manuell: Ermessen"));
        var html = ReportExporter.ToHtml(report, de);
        Assert.IsTrue(html.Contains("Kapitel: Kap") && html.Contains("Hinweis 26H2: Notiz"));
        Assert.IsTrue(html.Contains("Konten &amp; UAC"), "category label should be HTML-encoded");
    }
}

[TestClass]
public sealed class LocalizationTests
{
    private static string AppDir()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "AppSrc");
        if (Directory.Exists(dir)) return dir;
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.App"));
    }

    private static HashSet<string> ReswKeys(string culture)
    {
        var file = Path.Combine(AppDir(), "Strings", culture, "Resources.resw");
        Assert.IsTrue(File.Exists(file), $"resw fehlt: {file}");
        var keys = new HashSet<string>();
        foreach (var line in File.ReadAllLines(file))
        {
            var m = System.Text.RegularExpressions.Regex.Match(line, @"<data name=""([^""]+)""");
            if (m.Success) keys.Add(m.Groups[1].Value);
        }
        return keys;
    }

    private static HashSet<string> ReferencedKeys()
    {
        var used = new HashSet<string>();
        // Nur Quellverzeichnisse, keine Build-Artefakte (obj/bin enthalten stale Kopien)
        foreach (var xaml in Directory.EnumerateFiles(AppDir(), "*.xaml", SearchOption.AllDirectories)
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")))
        {
            var text = File.ReadAllText(xaml);
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"x:Uid=""([^""]+)"""))
                used.Add(m.Groups[1].Value);
        }
        foreach (var cs in Directory.EnumerateFiles(Path.Combine(AppDir(), "Pages"), "*.xaml.cs")
                     .Concat(Directory.EnumerateFiles(Path.Combine(AppDir(), "Services"), "*.cs"))
                     .Concat(Directory.EnumerateFiles(AppDir(), "MainWindow.xaml.cs")))
        {
            var text = File.ReadAllText(cs);
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"L\.(?:Get|F)\(""([^""]+)"""))
                used.Add(m.Groups[1].Value);
        }
        return used;
    }

    [TestMethod]
    public void English_Resources_Are_Complete()
    {
        var en = ReswKeys("en-US");
        var de = ReswKeys("de-DE");
        Assert.IsTrue(en.Count > 50, $"zu wenige EN-Keys: {en.Count}");
        Assert.IsTrue(de.Count > 50, $"zu wenige DE-Keys: {de.Count}");
        // Beide Sprachen müssen exakt dieselben Keys haben (Fallback wäre sonst unvollständig)
        Assert.AreEqual(0, en.Except(de).Count(), "Nur in en-US: " + string.Join(", ", en.Except(de)));
        Assert.AreEqual(0, de.Except(en).Count(), "Nur in de-DE: " + string.Join(", ", de.Except(en)));
    }

    [TestMethod]
    public void Xaml_Uids_Have_Resources()
    {
        foreach (var culture in new[] { "en-US", "de-DE" })
        {
            var keys = ReswKeys(culture);
            var problems = new List<string>();
            foreach (var xaml in Directory.EnumerateFiles(AppDir(), "*.xaml", SearchOption.AllDirectories)
                         .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")))
            {
                var text = File.ReadAllText(xaml);
                foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"x:Uid=""([^""]+)"""))
                {
                    var uid = m.Groups[1].Value;
                    if (!keys.Any(k => k == uid || k.StartsWith(uid + ".")))
                        problems.Add($"{culture}/{Path.GetFileName(xaml)}: x:Uid={uid} ohne resw-Key");
                }
            }
            Assert.AreEqual(0, problems.Count, string.Join("\n", problems.Take(15)));
        }
    }

    [TestMethod]
    public void Code_Keys_Have_Resources()
    {
        foreach (var culture in new[] { "en-US", "de-DE" })
        {
            var keys = ReswKeys(culture);
            var problems = new List<string>();
            foreach (var cs in Directory.EnumerateFiles(Path.Combine(AppDir(), "Pages"), "*.xaml.cs")
                         .Concat(Directory.EnumerateFiles(Path.Combine(AppDir(), "Services"), "*.cs"))
                         .Concat(Directory.EnumerateFiles(AppDir(), "MainWindow.xaml.cs")))
            {
                var text = File.ReadAllText(cs);
                foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"L\.(?:Get|F)\(""([^""]+)""\)"))
                {
                    var key = m.Groups[1].Value;
                    if (key.StartsWith("Core")) continue; // Core-Keys werden dynamisch ("Core"+key) aufgelöst, siehe CoreStrings
                    if (!keys.Contains(key))
                        problems.Add($"{culture}/{Path.GetFileName(cs)}: L-Key={key} fehlt");
                }
            }
            Assert.AreEqual(0, problems.Count, string.Join("\n", problems.Take(15)));
        }
    }

    [TestMethod]
    public void No_Orphan_Resource_Keys()
    {
        foreach (var culture in new[] { "en-US", "de-DE" })
        {
            var keys = ReswKeys(culture);
            var used = ReferencedKeys();
            var orphans = keys.Where(k =>
            {
                if (k.StartsWith("Core")) return false; // dynamisch via CoreStrings.Override referenziert
                var uid = k.Contains('.') ? k[..k.IndexOf('.')] : k;
                return !used.Contains(uid) && !used.Contains(k);
            }).ToList();
            Assert.AreEqual(0, orphans.Count, $"{culture} verwaiste Keys: " + string.Join(", ", orphans));
        }
    }
}

[TestClass]
public sealed class OverlayTests
{
    private static string WriteTmpRules()
    {
        var dir = Path.Combine(Path.GetTempPath(), "wha-overlay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(dir, "l10n"));
        File.WriteAllText(Path.Combine(dir, "r.json"),
            """[{"id":"O1","title":"Deutscher Titel","description":"Deutsche Beschreibung","category":"accounts-uac","severity":2,"check":{"provider":"manual"},"fixHint":"Deutscher Hinweis","profil":"L1","ziel":"both","giltAb":"24H2"}]""");
        File.WriteAllText(Path.Combine(dir, "l10n", "en.json"),
            """{"O1":{"title":"English title","description":"English description","fixHint":"English hint"},"UNKNOWN":{"title":"x"}}""");
        return dir;
    }

    [TestMethod]
    public void Overlay_Merges_English_And_Ignores_Unknown_Ids()
    {
        var dir = WriteTmpRules();
        try
        {
            var rules = CheckRunner.LoadRulesFromDirectory(dir, "en");
            Assert.AreEqual(1, rules.Count);
            Assert.AreEqual("English title", rules[0].Title);
            Assert.AreEqual("English description", rules[0].Description);
            Assert.AreEqual("English hint", rules[0].FixHint);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [TestMethod]
    public void Overlay_Falls_Back_To_German()
    {
        var dir = WriteTmpRules();
        try
        {
            var de = CheckRunner.LoadRulesFromDirectory(dir, "de");
            Assert.AreEqual("Deutscher Titel", de[0].Title);
            var fr = CheckRunner.LoadRulesFromDirectory(dir, "fr");
            Assert.AreEqual("Deutscher Titel", fr[0].Title);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    private static string ShippedRulesDir()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules");
        if (!Directory.Exists(dir))
        {
            dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.Core", "Rules"));
        }
        return dir;
    }

    [TestMethod]
    public void Shipped_Overlay_Covers_All_Rule_Ids()
    {
        var dir = ShippedRulesDir();
        var rules = CheckRunner.LoadRulesFromDirectory(dir);
        Assert.IsTrue(rules.Count >= 40, $"Expected >= 40 rules, found: {rules.Count}");
        var overlayFile = Path.Combine(dir, "l10n", "en.json");
        Assert.IsTrue(File.Exists(overlayFile), $"overlay missing: {overlayFile}");
        var overlay = JsonSerializer.Deserialize<Dictionary<string, CheckRunner.RuleOverlay>>(
            File.ReadAllText(overlayFile), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.IsNotNull(overlay);
        var ids = rules.Select(r => r.Id).ToHashSet();
        Assert.AreEqual(0, overlay.Keys.Except(ids).Count(), "Unknown overlay IDs: " + string.Join(",", overlay.Keys.Except(ids).Take(10)));
        Assert.AreEqual(0, ids.Except(overlay.Keys).Count(), "Missing overlay IDs: " + string.Join(",", ids.Except(overlay.Keys).Take(10)));
        var merged = CheckRunner.LoadRulesFromDirectory(dir, "en");
        Assert.AreEqual(rules.Count, merged.Count);
        Assert.AreEqual(0, CheckRunner.ValidateRules(merged).Count, "Merged EN rules invalid:\n" + string.Join("\n", CheckRunner.ValidateRules(merged).Take(10)));
        Assert.IsTrue(merged.Any(r => r.Title.Contains("password", StringComparison.OrdinalIgnoreCase)), "Expected merged English titles");
    }
}
