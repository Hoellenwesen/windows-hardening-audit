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
    [DataRow("3", "1..5", "Between", true)]
    [DataRow("1", "1..5", "Between", true)]
    [DataRow("5", "1..5", "Between", true)]
    [DataRow("0", "1..5", "Between", false)]
    [DataRow("6", "1..5", "Between", false)]
    [DataRow("0", "0,15..", "Between", true)]
    [DataRow("14", "0,15..", "Between", false)]
    [DataRow("15", "0,15..", "Between", true)]
    [DataRow("999", "0,15..", "Between", true)]
    [DataRow("-1", "1..365", "Between", false)]
    [DataRow("365", "1..365", "Between", true)]
    [DataRow("n/a", "1..5", "Between", false)]
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
        Assert.IsGreaterThanOrEqualTo(40, rules.Count, $"Erwartet >= 40 Regeln, gefunden: {rules.Count}");
        var dupes = rules.GroupBy(r => r.Id).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.IsEmpty(dupes, "Doppelte IDs: " + string.Join(",", dupes));
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
    [DataRow("3", "1..5", "Between", true)]
    [DataRow("0", "1..5", "Between", false)]
    [DataRow("-1", "1..365", "Between", false)]
    [DataRow("0", "0,15..", "Between", true)]
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
        Assert.IsEmpty(problems, "Validierungsfehler:\n" + string.Join("\n", problems.Take(20)));
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
        var good = new[]
        {
            R("G1", "registry", "Equals") with
            {
                Profil = "L1",
                Remediation = new RemediationSpec
                {
                    Mode = "auto", Risk = "low",
                    Actions = new List<RemediationAction>
                    {
                        new() { Type = "registry", Key = "HKLM\\SOFTWARE\\X", ValueName = "V", ValueType = "dword", Value = "1" }
                    }
                }
            },
            R("G2", "manual", "Equals") with { Profil = "MS" }
        };
        Assert.IsEmpty(CheckRunner.ValidateRules(good));
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
        Assert.HasCount(3, lines);
        Assert.StartsWith("Id;Title;Category;Status;", lines[0]);
        Assert.IsTrue(lines[1].Contains("Not met") && lines[1].Contains("X1"));
        Assert.Contains("Manual: Judgment", lines[2]);
        Assert.Contains("Both", lines[1], "target key 'both' should render as Both");
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
        Assert.StartsWith("Id;Titel;Rubrik;Status;", lines[0]);
        Assert.IsTrue(lines[1].Contains("Nicht erfüllt") && lines[1].Contains("X1"));
        Assert.Contains("Manuell: Ermessen", lines[2]);
        var html = ReportExporter.ToHtml(report, de);
        Assert.IsTrue(html.Contains("Kapitel: Kap") && html.Contains("Hinweis 26H2: Notiz"));
        Assert.Contains("Konten &amp; UAC", html, "category label should be HTML-encoded");
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
        Assert.IsGreaterThan(50, en.Count, $"zu wenige EN-Keys: {en.Count}");
        Assert.IsGreaterThan(50, de.Count, $"zu wenige DE-Keys: {de.Count}");
        // Beide Sprachen müssen exakt dieselben Keys haben (Fallback wäre sonst unvollständig)
        Assert.HasCount(0, en.Except(de), "Nur in en-US: " + string.Join(", ", en.Except(de)));
        Assert.HasCount(0, de.Except(en), "Nur in de-DE: " + string.Join(", ", de.Except(en)));
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
            Assert.HasCount(0, problems, string.Join("\n", problems.Take(15)));
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
            Assert.HasCount(0, problems, string.Join("\n", problems.Take(15)));
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
            Assert.IsEmpty(orphans, $"{culture} verwaiste Keys: " + string.Join(", ", orphans));
        }
    }
}

[TestClass]
public sealed class RuleScriptRegressionTests
{
    private static List<RuleDefinition> ShippedRules()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules");
        if (!Directory.Exists(dir))
            dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.Core", "Rules"));
        return CheckRunner.LoadRulesFromDirectory(dir);
    }

    private static IEnumerable<RuleDefinition> ScriptRules()
        => ShippedRules().Where(r => r.Check.Provider == "script" && !string.IsNullOrWhiteSpace(r.Check.Script));

    [TestMethod]
    public void Shipped_Rule_Count_Does_Not_Shrink()
    {
        Assert.IsGreaterThanOrEqualTo(536, ShippedRules().Count, "Regeln verloren gegangen");
    }

    [TestMethod]
    public void No_Service_Lookup_By_Localized_DisplayName()
    {
        // Anzeigenamen von Diensten sind Ressourcen-Strings (@...dll,-100) und damit sprachabhängig.
        var bad = ScriptRules()
            .Where(r => r.Check.Script!.Contains("Get-Service -DisplayName", StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Id).ToList();
        Assert.IsEmpty(bad, "Dienst-Lookup über Anzeigename: " + string.Join(", ", bad));
    }

    [TestMethod]
    public void No_Localized_Strings_As_Filters()
    {
        var bad = ScriptRules()
            .Where(r => r.Check.Script!.Contains("Local Group Policy", StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Id).ToList();
        Assert.IsEmpty(bad, "Lokalisierter String als Filter: " + string.Join(", ", bad));
    }

    [TestMethod]
    public void No_Catch_Block_That_Returns_The_Expected_Value()
    {
        // Ein catch, das den Sollwert liefert, macht aus jedem Fehler (z. B. fehlende Elevation) ein "Passed".
        var bad = new List<string>();
        foreach (var r in ScriptRules())
        {
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(r.Check.Script!, @"catch\s*\{\s*'([^']*)'\s*\}"))
            {
                if (string.Equals(m.Groups[1].Value.Trim(), (r.Check.Expected ?? "").Trim(), StringComparison.OrdinalIgnoreCase))
                    bad.Add($"{r.Id} (catch {{ {m.Groups[1].Value} }})");
            }
        }
        Assert.IsEmpty(bad, "catch liefert den Sollwert: " + string.Join(", ", bad));
    }

    [TestMethod]
    public void Auditpol_Uses_Guid_And_Normalizes_Localized_Settings()
    {
        var rules = ScriptRules()
            .Where(r => r.Check.Script!.Contains("auditpol", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.IsGreaterThanOrEqualTo(30, rules.Count, "auditpol-Regeln fehlen");
        foreach (var r in rules)
        {
            var s = r.Check.Script!;
            Assert.IsFalse(System.Text.RegularExpressions.Regex.IsMatch(s, @"/subcategory:'[A-Za-z]"),
                $"{r.Id}: Subkategorie über Anzeigename statt GUID");
            Assert.IsTrue(System.Text.RegularExpressions.Regex.IsMatch(s, @"0cce[0-9a-fA-F]{4}-"),
                $"{r.Id}: keine Subkategorie-GUID im Skript");
            Assert.IsTrue(s.Contains("Erfolg", StringComparison.Ordinal) && s.Contains("Fehler", StringComparison.Ordinal)
                          && s.Contains("Keine", StringComparison.Ordinal),
                $"{r.Id}: keine Normalisierung der deutschen Inclusion-Setting-Werte");
        }
    }

    [TestMethod]
    public void Scripts_Must_Not_Contain_Double_Quotes()
    {
        // ScriptProvider.Escape() ersetzt " still durch ' – ein Skript mit " würde unbemerkt verfälscht.
        var bad = ScriptRules().Where(r => r.Check.Script!.Contains('"')).Select(r => r.Id).ToList();
        Assert.IsEmpty(bad, "Skript mit doppeltem Anführungszeichen: " + string.Join(", ", bad));
    }

    [TestMethod]
    public void Svc03_Only_Checks_Baseline_Services()
    {
        // Die MS-Baseline deaktiviert nur die vier Xbox-Dienste; "Xbox Service" läuft per Default auf Automatic.
        var s = ShippedRules().Single(x => x.Id == "SVC-03").Check.Script!;
        foreach (var name in new[] { "XboxGipSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc" })
            Assert.Contains(name, s, $"SVC-03 prüft {name} nicht");
        Assert.DoesNotContain("XboxService", s, "SVC-03 prüft 'Xbox Service', der nicht in der Baseline steht");
        Assert.DoesNotContain("^(Xbox|Xbl)", s, "SVC-03 darf nicht per Präfix filtern");
    }

    [TestMethod]
    public void Lap01_Checks_Machine_Relative_Rid_500()
    {
        var r = ShippedRules().Single(x => x.Id == "LAP-01");
        Assert.DoesNotContain("S-1-5-500", r.Check.Script!, "LAP-01 nutzt die nie existierende SID S-1-5-500");
        Assert.Contains("-500$", r.Check.Script!, "LAP-01 muss die RID des lokalen Kontos prüfen");
    }

    [TestMethod]
    public void CisSourceIds_Are_Precise()
    {
        // "CIS 5.x", "CIS 19.x" oder eine Gruppenebene ("CIS 2.3.7") sind keine belastbaren Kontrollnummern.
        var bad = new List<string>();
        foreach (var r in ShippedRules().Where(x => x.Profil == "L1"))
        {
            if (!(r.Source?.Contains("CIS", StringComparison.OrdinalIgnoreCase) ?? false)) continue;
            var sid = r.SourceId ?? "";
            if (sid.Contains('x') || sid.Contains('X'))
                bad.Add($"{r.Id}: Platzhalter [{sid}]");
            else if (System.Text.RegularExpressions.Regex.IsMatch(sid, @"^CIS \d")
                     && !System.Text.RegularExpressions.Regex.IsMatch(sid,
                         @"^CIS \d+(\.\d+)+( / \d+(\.\d+)+)? \((L[12]|BL-Add-on)\)$"))
                bad.Add($"{r.Id}: Format [{sid}]");
        }
        Assert.IsEmpty(bad, "CIS-Kontrollnummer unpräzise: " + string.Join(", ", bad));
    }

    [TestMethod]
    public void L1_Profile_Contains_No_L2_Controls()
    {
        // Beide sind in CIS Windows 11 v5.0.0 L2 (5.24 bzw. 18.10.88.1).
        var l1 = ShippedRules().Where(r => r.Profil == "L1").Select(r => r.Id).ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain("AUD-01", l1, "AUD-01 (Script Block Logging) ist L2");
        Assert.DoesNotContain("SVC-01", l1, "SVC-01 (RemoteRegistry) ist L2");
    }

    [TestMethod]
    public void Account_Policies_Use_Cis_Ranges()
    {
        var rules = ShippedRules().ToDictionary(r => r.Id, StringComparer.Ordinal);
        Assert.AreEqual("Between", rules["ACCT-15"].Check.Operator);
        Assert.AreEqual("1..5", rules["ACCT-15"].Check.Expected, "CIS 1.2.2 erlaubt 1-5, nicht nur exakt 5");
        Assert.AreEqual("Between", rules["ACCT-13"].Check.Operator);
        Assert.AreEqual("1..365", rules["ACCT-13"].Check.Expected, "CIS 1.1.2 erlaubt 1-365 und schließt -1/0 aus");
        Assert.AreEqual("Between", rules["ACCT-16"].Check.Operator);
        Assert.AreEqual("0,15..", rules["ACCT-16"].Check.Expected, "Dauer 0 (bis Admin entsperrt) ist konform");
    }

    [TestMethod]
    public void Cis_Thresholds_Match_V5()
    {
        var rules = ShippedRules().ToDictionary(r => r.Id, StringComparer.Ordinal);
        Assert.AreEqual("2", rules["NTLM-01"].Check.Expected, "CIS 2.3.11.11 verlangt 'alle Konten' (2)");
        Assert.AreEqual("201326592", rules["AUD-05"].Check.Expected, "CIS 18.10.26.2.2 verlangt 196608 KB = 201326592 Bytes");
    }

    [TestMethod]
    public void Secedit_Privilege_Rights_Use_Sid_Values()
    {
        var bad = ShippedRules()
            .Where(r => r.Check.Provider == "secedit"
                        && string.Equals(r.Check.Key, "PrivilegeRights", StringComparison.OrdinalIgnoreCase)
                        && !string.IsNullOrWhiteSpace(r.Check.Expected))
            .Where(r => !System.Text.RegularExpressions.Regex.IsMatch(r.Check.Expected!,
                @"^\*?S-1-5-[\d-]+(,\s*\*?S-1-5-[\d-]+)*$"))
            .Select(r => $"{r.Id}=[{r.Check.Expected}]")
            .ToList();
        Assert.IsEmpty(bad, "Privilege-Rights-Sollwert ist keine SID-Liste: " + string.Join(", ", bad));
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
            Assert.HasCount(1, rules);
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
        Assert.IsGreaterThanOrEqualTo(40, rules.Count, $"Expected >= 40 rules, found: {rules.Count}");
        var overlayFile = Path.Combine(dir, "l10n", "en.json");
        Assert.IsTrue(File.Exists(overlayFile), $"overlay missing: {overlayFile}");
        var overlay = JsonSerializer.Deserialize<Dictionary<string, CheckRunner.RuleOverlay>>(
            File.ReadAllText(overlayFile), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.IsNotNull(overlay);
        var ids = rules.Select(r => r.Id).ToHashSet();
        Assert.HasCount(0, overlay.Keys.Except(ids), "Unknown overlay IDs: " + string.Join(",", overlay.Keys.Except(ids).Take(10)));
        Assert.HasCount(0, ids.Except(overlay.Keys), "Missing overlay IDs: " + string.Join(",", ids.Except(overlay.Keys).Take(10)));
        var merged = CheckRunner.LoadRulesFromDirectory(dir, "en");
        Assert.HasCount(merged.Count, rules);
        Assert.IsEmpty(CheckRunner.ValidateRules(merged), "Merged EN rules invalid:\n" + string.Join("\n", CheckRunner.ValidateRules(merged).Take(10)));
        Assert.IsTrue(merged.Any(r => r.Title.Contains("password", StringComparison.OrdinalIgnoreCase)), "Expected merged English titles");
    }
}

[TestClass]
public sealed class RemediationTests
{
    private static List<RuleDefinition> ShippedRules()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules");
        if (!Directory.Exists(dir))
            dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.Core", "Rules"));
        return CheckRunner.LoadRulesFromDirectory(dir);
    }

    private static List<RuleDefinition> L1() => ShippedRules().Where(r => r.Profil == "L1").ToList();

    [TestMethod]
    public void L1_Remediation_Modes_Are_Consistent()
    {
        var l1 = L1();
        Assert.IsGreaterThanOrEqualTo(90, l1.Count, $"Expected >= 90 L1 rules, found {l1.Count}");
        var auto = l1.Where(r => r.Remediation?.Mode == "auto").ToList();
        var manual = l1.Where(r => r.Remediation?.Mode == "manual").ToList();
        Assert.HasCount(l1.Count, auto.Concat(manual), "Every L1 rule needs mode auto or manual");
        Assert.IsGreaterThanOrEqualTo(40, auto.Count, $"Expected >= 40 auto-fixable, found {auto.Count}");
        Assert.IsEmpty(auto.Where(r => r.Remediation!.Risk == "high").Select(r => r.Id),
            "High-risk rules must not be auto-fixable");
        Assert.IsEmpty(auto.Where(r => string.IsNullOrWhiteSpace(r.Remediation!.Gui)).Select(r => r.Id),
            "Auto rules without GUI path");
        Assert.IsEmpty(manual.Where(r => string.IsNullOrWhiteSpace(r.Remediation!.Gui)
                || r.Remediation!.Steps.Count < 2).Select(r => r.Id),
            "Manual rules need a GUI path and at least 2 steps");
    }

    [TestMethod]
    public void Auto_Registry_Actions_Match_Check_Key()
    {
        // The fix must write exactly the value the check reads (catches HKLM/HKCU mix-ups).
        var bad = new List<string>();
        foreach (var r in L1().Where(r => r.Remediation?.Mode == "auto"
            && string.Equals(r.Check.Provider, "registry", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var a in r.Remediation!.Actions.Where(a => a.Type == "registry"))
            {
                if (!string.Equals(a.Key?.Trim(), r.Check.Key?.Trim(), StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(a.ValueName?.Trim(), r.Check.ValueName?.Trim(), StringComparison.OrdinalIgnoreCase))
                    bad.Add($"{r.Id}: action {a.Key}\\{a.ValueName} vs check {r.Check.Key}\\{r.Check.ValueName}");
            }
        }
        Assert.IsEmpty(bad, "Remediation writes a different value than the check reads:\n" + string.Join("\n", bad));
    }

    [TestMethod]
    public void Auto_Action_Value_Satisfies_Check_Operator()
    {
        var bad = new List<string>();
        foreach (var r in L1().Where(r => r.Remediation?.Mode == "auto"))
        {
            foreach (var a in r.Remediation!.Actions)
            {
                if (a.Type == "registry" && string.Equals(r.Check.Provider, "registry", StringComparison.OrdinalIgnoreCase))
                {
                    if (!RegistryProvider.Compare(a.Value ?? "", r.Check.Expected ?? "", r.Check.Operator))
                        bad.Add($"{r.Id}: value {a.Value} fails {r.Check.Operator} {r.Check.Expected}");
                }
                else if (a.Type == "secedit" && string.Equals(r.Check.Provider, "secedit", StringComparison.OrdinalIgnoreCase)
                         && string.Equals(a.ValueName, r.Check.ValueName, StringComparison.OrdinalIgnoreCase))
                {
                    if (!SeceditProvider.CompareSecedit(a.Value ?? "", r.Check.Expected ?? "", r.Check.Operator))
                        bad.Add($"{r.Id}: value {a.Value} fails {r.Check.Operator} {r.Check.Expected}");
                }
            }
        }
        Assert.IsEmpty(bad, "Fix value does not satisfy the check:\n" + string.Join("\n", bad));
    }

    [TestMethod]
    public void Describe_Summarizes_Every_Action_Type()
    {
        var markers = new Dictionary<string, string>
        {
            ["registry"] = "HKLM", ["service"] = "Disabled", ["account"] = "Guest",
            ["auditpol"] = "0cce9215", ["eventlog"] = "Security", ["firewallProfile"] = "Domain",
            ["smb"] = "SMB", ["netaccounts"] = "maxpwage", ["secedit"] = "PasswordComplexity",
        };
        foreach (var type in CheckRunner.ValidRemediationTypes)
        {
            var a = new RemediationAction
            {
                Type = type, Key = "HKLM\\SOFTWARE\\X", ValueName = "PasswordComplexity",
                ValueType = "dword", Value = "1",
                Name = "Guest", StartType = "Disabled", Subcategory = "0cce9215-69ae-11d9-bed3-505054503030",
                Success = true, Failure = true, Log = "Security", MaxSizeBytes = 1,
                Profile = "Domain", Enabled = true, Switch = "maxpwage",
            };
            if (type == "account") a = a with { Name = "Guest" };
            var s = RemediationScript.Describe(a);
            Assert.IsFalse(string.IsNullOrWhiteSpace(s), $"Describe empty for {type}");
            Assert.Contains(markers[type], s, $"Describe uninformative for {type}: {s}");
        }
    }

    [TestMethod]
    public void CanAutoFix_Gates_Mode_Profile_And_Actions()
    {
        var l1 = L1().ToDictionary(r => r.Id);
        Assert.IsTrue(RemediationRunner.CanAutoFix(l1["ACCT-02"]));
        Assert.IsFalse(RemediationRunner.CanAutoFix(l1["BOOT-01"]), "Manual rule must not be auto-fixable");
        var l2 = l1["ACCT-02"] with { Profil = "L2" };
        Assert.IsFalse(RemediationRunner.CanAutoFix(l2), "L2 rules are out of scope for one-click fix");
        var noActions = l1["ACCT-02"] with
        {
            Remediation = l1["ACCT-02"].Remediation! with { Actions = new List<RemediationAction>() }
        };
        Assert.IsFalse(RemediationRunner.CanAutoFix(noActions));
    }

    [TestMethod]
    public void Undo_Registry_Roundtrip_On_Hkcu()
    {
        // HKCU needs no admin rights, safe on any machine. Always cleans up.
        const string key = "HKCU\\Software\\WinHardeningAuditTest\\Remediation";
        var action = new RemediationAction
        {
            Type = "registry", Key = key, ValueName = "Probe", ValueType = "dword", Value = "1",
        };
        var before = PowerShellFile.RunAsync(RemediationScript.Snapshot(action)).GetAwaiter().GetResult();
        Assert.IsTrue(before.Ok, "Snapshot failed: " + before.Text);
        string? backupApply = null;
        try
        {
            var apply = PowerShellFile.RunAsync(RemediationScript.Apply(action)).GetAwaiter().GetResult();
            Assert.IsTrue(apply.Ok, "Apply failed: " + apply.Text);
            backupApply = apply.Text;
            var verify = PowerShellFile.RunAsync(RemediationScript.Snapshot(action)).GetAwaiter().GetResult();
            Assert.IsTrue(verify.Ok && verify.Text.Contains("\"existed\":true", StringComparison.OrdinalIgnoreCase),
                "Value not written: " + verify.Text);
            var undo = RemediationScript.UndoFromSnapshot(action, before.Text);
            Assert.IsFalse(string.IsNullOrWhiteSpace(undo), "Undo script empty");
            var undone = PowerShellFile.RunAsync(undo).GetAwaiter().GetResult();
            Assert.IsTrue(undone.Ok, "Undo failed: " + undone.Text);
        }
        finally
        {
            PowerShellFile.RunAsync($"Remove-Item -Path 'HKCU:\\Software\\WinHardeningAuditTest' -Recurse -Force -ErrorAction SilentlyContinue")
                .GetAwaiter().GetResult();
        }
        Assert.IsNotNull(backupApply);
    }

    [TestMethod]
    public void Apply_Propagates_Native_Tool_Exit_Codes()
    {
        var auditpol = RemediationScript.Apply(new RemediationAction
            { Type = "auditpol", Subcategory = "0cce9215-69ae-11d9-bed3-505054503030", Success = true, Failure = true });
        Assert.Contains("LASTEXITCODE", auditpol, "auditpol failure would report success");
        var eventlog = RemediationScript.Apply(new RemediationAction
            { Type = "eventlog", Log = "Security", MaxSizeBytes = 1 });
        Assert.Contains("LASTEXITCODE", eventlog, "wevtutil failure would report success");
        var netacc = RemediationScript.Apply(new RemediationAction
            { Type = "netaccounts", Switch = "maxpwage", Value = "365" });
        Assert.Contains("LASTEXITCODE", netacc, "net accounts failure would report success");
        var secedit = RemediationScript.Apply(new RemediationAction
            { Type = "secedit", ValueName = "PasswordComplexity", Value = "1" });
        Assert.Contains("LASTEXITCODE", secedit, "secedit export failure would corrupt policy");
    }

    [TestMethod]
    public void Undo_Fails_Closed_On_Unusable_Snapshots()
    {
        var cases = new (RemediationAction Action, string Snapshot)[]
        {
            (new() { Type = "eventlog", Log = "Security" }, "{}"),
            (new() { Type = "firewallProfile", Profile = "Domain" }, "{}"),
            (new() { Type = "smb" }, "{}"),
            (new() { Type = "account" }, "{}"),
            (new() { Type = "account" }, """{"name":"","enabled":false}"""),
            (new() { Type = "service", Name = "Spooler" }, "{}"),
            (new() { Type = "auditpol", Subcategory = "0cce9215-69ae-11d9-bed3-505054503030" }, "{}"),
            (new() { Type = "netaccounts", Switch = "maxpwage" }, "{}"),
        };
        foreach (var (action, snapshot) in cases)
        {
            Assert.AreEqual("", RemediationScript.UndoFromSnapshot(action, snapshot).Trim(),
                $"Undo must be empty (fail closed) for {action.Type}, got a guessed script");
        }
        // Valid snapshots still produce working undo scripts.
        Assert.Contains("Remove-ItemProperty",
            RemediationScript.UndoFromSnapshot(
                new() { Type = "registry", Key = "HKLM\\SOFTWARE\\X", ValueName = "V" }, "{}"));
        Assert.Contains("wevtutil sl Security /ms:123",
            RemediationScript.UndoFromSnapshot(
                new() { Type = "eventlog", Log = "Security" }, """{"type":"eventlog","bytes":123}"""));
        Assert.Contains("Set-Service -Name 'Spooler' -StartupType Disabled",
            RemediationScript.UndoFromSnapshot(
                new() { Type = "service", Name = "Spooler" }, """{"startType":"Disabled"}"""));
    }

    [TestMethod]
    public void Missing_AllowAdministratorLockout_Is_Not_Auto_Pass()
    {
        var rule = ShippedRules().Single(r => r.Id == "ACCT-18");
        Assert.AreNotEqual("Passed", rule.Check.MissingIs,
            "Unconfigured admin lockout must fail, the OS default does not lock the administrator account");
    }

    [TestMethod]
    public void Enc04_Requires_Uefi_Lock_Value()
    {
        // Baseline decision: RunAsPPL = 1 (with UEFI lock); 2 (without lock) is not compliant.
        var rule = ShippedRules().Single(r => r.Id == "ENC-04");
        Assert.AreEqual("Equals", rule.Check.Operator);
        Assert.AreEqual("1", rule.Check.Expected);
        var action = rule.Remediation!.Actions.Single(a => a.Type == "registry");
        Assert.AreEqual("1", action.Value, "Fix must set the baseline value, not a weaker one");
    }

    [TestMethod]
    public void Ntp_Rules_Split_By_Target()
    {
        // Same setting, complementary targets: exactly one applies per machine.
        // In the "Both" view one of them is therefore red by design.
        var rules = ShippedRules().Where(r => r.Id is "NTP-02" or "NTP-03").ToDictionary(r => r.Id);
        Assert.AreEqual("standalone", rules["NTP-02"].Ziel);
        Assert.AreEqual("NTP", rules["NTP-02"].Check.Expected);
        Assert.AreEqual("enterprise", rules["NTP-03"].Ziel);
        Assert.AreEqual("NT5DS", rules["NTP-03"].Check.Expected);
        Assert.AreEqual(rules["NTP-02"].Check.Key, rules["NTP-03"].Check.Key);
    }

    [TestMethod]
    public void Service_Snapshot_Tracks_Delayed_Start()
    {
        var snap = PowerShellFile.RunAsync(
            RemediationScript.Snapshot(new() { Type = "service", Name = "Spooler" })).GetAwaiter().GetResult();
        Assert.IsTrue(snap.Ok, "Snapshot failed: " + snap.Text);
        Assert.Contains("delayed", snap.Text.ToLowerInvariant(), "Snapshot lost DelayedAutoStart: " + snap.Text);
        var undoDelayed = RemediationScript.UndoFromSnapshot(
            new() { Type = "service", Name = "Spooler" }, """{"startType":"Automatic","delayed":true}""");
        Assert.Contains("delayed-auto", undoDelayed, "Delayed start not restored: " + undoDelayed);
        var undoPlain = RemediationScript.UndoFromSnapshot(
            new() { Type = "service", Name = "Spooler" }, """{"startType":"Manual","delayed":false}""");
        Assert.DoesNotContain("delayed-auto", undoPlain, "Spurious delayed-auto: " + undoPlain);
    }

    [TestMethod]
    public void SeceditApply_Escapes_Keys_And_Tolerates_Header_Case()
    {
        var script = RemediationScript.Apply(new RemediationAction
            { Type = "secedit", ValueName = "A+B", Value = "1" });
        Assert.Contains("A\\+B", script, "Regex metacharacters must be escaped");
        Assert.Contains("system access", script.ToLowerInvariant(), "Section header lookup missing");
    }

    [TestMethod]
    public void Binary_Registry_Values_Are_Not_Guessed_Back()
    {
        var undo = RemediationScript.UndoFromSnapshot(
            new() { Type = "registry", Key = "HKLM\\SOFTWARE\\X", ValueName = "V" },
            """{"existed":true,"value":[1,2,3],"kind":"Binary"}""");
        Assert.AreEqual("", undo, "Binary blob must fail closed, got: " + undo);
    }

    [TestMethod]
    public async Task UndoAsync_Runs_Entries_In_Reverse_Order()
    {
        var dir = Path.Combine(Path.GetTempPath(), "wha-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var log = Path.Combine(dir, "order.txt");
            var backup = new RemediationBackup
            {
                RuleId = "T",
                Entries = new List<RemediationBackupEntry>
                {
                    new("test", "first", $"Add-Content -Path '{log}' -Value 'first'"),
                    new("test", "second", $"Add-Content -Path '{log}' -Value 'second'"),
                },
            };
            var file = Path.Combine(dir, "backup.json");
            await File.WriteAllTextAsync(file, System.Text.Json.JsonSerializer.Serialize(backup));
            var outcome = await RemediationRunner.UndoAsync(file);
            Assert.IsTrue(outcome.Success, "Undo failed: " + outcome.Message);
            var lines = (await File.ReadAllLinesAsync(log)).Where(l => l is "first" or "second").ToList();
            CollectionAssert.AreEqual(new[] { "second", "first" }, lines, "Undo must run LIFO");
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [TestMethod]
    public void Snapshot_Of_Missing_Key_Yields_Removal_Undo()
    {
        var action = new RemediationAction
        {
            Type = "registry", Key = "HKCU\\Software\\WinHardeningAuditTest\\NoSuchKey",
            ValueName = "Nope", ValueType = "dword", Value = "1",
        };
        var snap = PowerShellFile.RunAsync(RemediationScript.Snapshot(action)).GetAwaiter().GetResult();
        Assert.IsTrue(snap.Ok, "Snapshot failed: " + snap.Text);
        var undo = RemediationScript.UndoFromSnapshot(action, snap.Text);
        Assert.Contains("Remove-ItemProperty", undo, "Missing key must be restored by removal, got: " + undo);
    }

    [TestMethod]
    public void English_Overlay_Covers_Remediation_Guides()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "Rules");
        if (!Directory.Exists(dir))
            dir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "WinHardeningAudit.Core", "Rules"));
        var overlay = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, CheckRunner.RuleOverlay>>(
            File.ReadAllText(Path.Combine(dir, "l10n", "en.json")),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.IsNotNull(overlay);
        var missingGui = new List<string>();
        var missingSteps = new List<string>();
        foreach (var r in L1())
        {
            if (!overlay.TryGetValue(r.Id, out var o) || o is null || string.IsNullOrWhiteSpace(o.Gui))
                missingGui.Add(r.Id);
            if (r.Remediation?.Mode == "manual" && (o?.Steps is not { Count: >= 2 }))
                missingSteps.Add(r.Id);
        }
        Assert.IsEmpty(missingGui, "EN overlay without GUI path: " + string.Join(",", missingGui));
        Assert.IsEmpty(missingSteps, "EN overlay without steps: " + string.Join(",", missingSteps));
    }

    [TestMethod]
    public void TryExtractCommand_Finds_Copyable_Commands()
    {
        Assert.AreEqual("Set-MpPreference -DisableRealtimeMonitoring $false",
            RemediationScript.TryExtractCommand("PowerShell (Admin): Set-MpPreference -DisableRealtimeMonitoring $false"));
        Assert.AreEqual("Set-MpPreference -MAPSReporting Advanced; Set-X -Y",
            RemediationScript.TryExtractCommand("PowerShell: Set-MpPreference -MAPSReporting Advanced; Set-X -Y"));
        Assert.AreEqual("Set-ItemProperty X -Value 1",
            RemediationScript.TryExtractCommand("PowerShell (Admin): Set-ItemProperty X -Value 1; Neustart."));
        Assert.AreEqual("New-ItemProperty HKCU:\\Software\\X -Name V -Value 4 -PropertyType DWord -Force",
            RemediationScript.TryExtractCommand("PowerShell: New-ItemProperty HKCU:\\Software\\X -Name V -Value 4 -PropertyType DWord -Force (Office 16.0 = 2016, adjust path)."));
        Assert.AreEqual("Set-MpPreference -DisableBehaviorMonitoring $false",
            RemediationScript.TryExtractCommand("PowerShell (Admin): Set-MpPreference -DisableBehaviorMonitoring $false (blocked when tamper protection is on)."));
        Assert.AreEqual("gpupdate /force",
            RemediationScript.TryExtractCommand("Apply domain GPOs: gpupdate /force (admin)."));
        Assert.AreEqual(@"Test-Path HKLM:\SOFTWARE\X\RebootPending",
            RemediationScript.TryExtractCommand(@"Verify: re-scan. PowerShell: Test-Path HKLM:\SOFTWARE\X\RebootPending ($false = OK)."));
        Assert.AreEqual("Get-NetFirewallRule | Where-Object { $_.Enabled }",
            RemediationScript.TryExtractCommand("Get-NetFirewallRule | Where-Object { $_.Enabled } (admin)."));
        Assert.AreEqual("auditpol /set /subcategory:x /success:enable",
            RemediationScript.TryExtractCommand("auditpol /set /subcategory:x /success:enable"));
        Assert.IsNull(RemediationScript.TryExtractCommand(
            "Settings > Windows Update > check for updates (internet required)."));
        Assert.IsNull(RemediationScript.TryExtractCommand(
            "GPO: Computer Configuration > Administrative Templates > configure the rule."));
        Assert.IsNull(RemediationScript.TryExtractCommand(""));
    }

    [TestMethod]
    public void Every_Manual_Step_With_PowerShell_Command_Yields_Copyable_Command()
    {
        var bad = new List<string>();
        foreach (var r in L1().Where(r => r.Remediation?.Mode == "manual"))
        {
            foreach (var s in r.Remediation!.Steps)
            {
                // Only steps that actually embed a command ("PowerShell ...: <cmd>").
                var ps = s.IndexOf("PowerShell", StringComparison.OrdinalIgnoreCase);
                if (ps < 0 || s.IndexOf(':', ps) < 0) continue;
                if (RemediationScript.TryExtractCommand(s) is not { Length: > 0 })
                    bad.Add($"{r.Id}: no command extracted from [{s}]");
            }
        }
        Assert.IsEmpty(bad, "PowerShell steps without copyable command:\n" + string.Join("\n", bad));
    }

    [TestMethod]
    public void LatestBackup_Finds_Newest_File_Per_Rule()
    {
        var dir = Path.Combine(Path.GetTempPath(), "wha-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        RemediationRunner.BackupDirOverride = dir;
        try
        {
            Assert.IsNull(RemediationRunner.LatestBackup("ACCT-02"), "Empty dir must yield null");
            File.WriteAllText(Path.Combine(dir, "20260101-120000-ACCT-02.json"), "{}");
            File.WriteAllText(Path.Combine(dir, "20260201-120000-ACCT-02.json"), "{}");
            File.WriteAllText(Path.Combine(dir, "20260301-120000-OTHER.json"), "{}");
            var latest = RemediationRunner.LatestBackup("ACCT-02");
            Assert.IsNotNull(latest);
            Assert.Contains("20260201-120000-ACCT-02.json", latest);
            Assert.IsNull(RemediationRunner.LatestBackup("ACCT-03"), "Other rules must not match");
        }
        finally
        {
            RemediationRunner.BackupDirOverride = null;
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [TestMethod]
    public void CollectFixable_Selects_Only_Actionable_L1_Findings()
    {
        CheckResult R(string id, string profil, string mode, CheckStatus status) => new()
        {
            Rule = new RuleDefinition
            {
                Id = id, Title = id, Category = "accounts-uac", Profil = profil,
                Remediation = new RemediationSpec
                {
                    Mode = mode,
                    Actions = mode == "auto"
                        ? new List<RemediationAction> { new() { Type = "registry" } }
                        : new List<RemediationAction>(),
                },
            },
            Status = status,
        };
        var results = new[]
        {
            R("A1", "L1", "auto", CheckStatus.Failed),   // in
            R("A2", "L1", "auto", CheckStatus.Warning),  // in
            R("P1", "L1", "auto", CheckStatus.Passed),    // out: already ok
            R("M1", "L1", "manual", CheckStatus.Failed),  // out: manual
            R("L1", "L2", "auto", CheckStatus.Failed),    // out: not L1
            R("MS", "MS", "auto", CheckStatus.Failed),    // out: not L1
            R("E1", "L1", "auto", CheckStatus.Error),     // out: not actionable
        };
        var fixable = RemediationPlanner.CollectFixable(results).Select(r => r.Rule.Id).ToList();
        CollectionAssert.AreEquivalent(new[] { "A1", "A2" }, fixable);
    }
}
