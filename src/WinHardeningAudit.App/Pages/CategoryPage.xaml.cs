using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinHardeningAudit.Core.Engine;
using WinHardeningAudit.Core.Models;
using WinHardeningAudit_App.Services;

namespace WinHardeningAudit_App.Pages;

public sealed partial class CategoryPage : Page
{
    private string _category = "";
    private readonly EventHandler _changedHandler;

    public CategoryPage()
    {
        InitializeComponent();
        _changedHandler = (_, _) => DispatcherQueue.TryEnqueue(Refresh);
        ScanService.Current.Changed += _changedHandler;
        SortBox.ItemsSource = ScanService.SortOrders.Select(ScanService.SortLabel).ToList();
        SortBox.SelectedIndex = 0;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        _category = e.Parameter as string ?? "";
        TitleText.Text = string.IsNullOrEmpty(_category) ? L.Get("FallbackCategory") : ScanService.CategoryLabel(_category);
        Refresh();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        ScanService.Current.Changed -= _changedHandler;
    }

    private void Filter_Changed(object sender, RoutedEventArgs e) => Refresh();
    private void Filter_Changed(object sender, TextChangedEventArgs e) => Refresh();
    private void Filter_Changed_Selection(object sender, SelectionChangedEventArgs e) => Refresh();

    private void Refresh()
    {
        if (string.IsNullOrEmpty(_category)) return;
        var svc = ScanService.Current;
        var items = svc.ForCategory(_category,
            onlyOpen: OnlyOpenToggle?.IsChecked == true,
            onlySevere: OnlySevereToggle?.IsChecked == true,
            search: SearchBox?.Text,
            sort: ScanService.SortFromLabel(SortBox?.SelectedItem as string ?? "")).ToList();
        var (t, p, f) = svc.CategoryCounts(_category);
        SummaryText.Text = t == 0
            ? L.F("CatSummaryNone", ScanService.ProfileLabel(svc.Profile), ScanService.TargetLabel(svc.Target))
            : L.F("CatSummary", p, t, f, items.Count, ScanService.ProfileLabel(svc.Profile), ScanService.TargetLabel(svc.Target));
        ResultList.ItemsSource = items.Select(ToRow).ToList();
    }

    private static object ToRow(CheckResult r)
    {
        var statusText = r.Status switch
        {
            CheckStatus.Passed => ScanService.StatusLabel(CheckStatus.Passed),
            CheckStatus.Failed => ScanService.StatusLabel(CheckStatus.Failed),
            CheckStatus.Manual => string.IsNullOrWhiteSpace(r.ManualKind)
                ? ScanService.StatusLabel(CheckStatus.Manual)
                : L.F("StatusManualKind", ScanService.ManualKindLabel(r.ManualKind)),
            CheckStatus.NotApplicable => ScanService.StatusLabel(CheckStatus.NotApplicable),
            CheckStatus.Warning => ScanService.StatusLabel(CheckStatus.Warning),
            _ => ScanService.StatusLabel(CheckStatus.Error),
        };
        var color = r.Status switch
        {
            CheckStatus.Passed => new SolidColorBrush(Colors.Green),
            CheckStatus.Failed => new SolidColorBrush(Colors.Red),
            CheckStatus.Manual => new SolidColorBrush(Colors.Gray),
            CheckStatus.NotApplicable => new SolidColorBrush(Colors.Gray),
            CheckStatus.Warning => new SolidColorBrush(Colors.DarkOrange),
            _ => new SolidColorBrush(Colors.Red),
        };
        return new
        {
            RuleId = r.Rule.Id,
            StatusText = statusText,
            StatusColor = color,
            SeverityText = ScanService.SeverityLabel(r.Rule.Severity),
            Title = $"{r.Rule.Title} ({r.Rule.Id})",
            Meta = $"{r.Rule.Source} {r.Rule.SourceId} · {L.Get("MetaSeverity")}: {ScanService.SeverityLabel(r.Rule.Severity)}",
            Details = string.Join(" · ", new[]
            {
                string.IsNullOrWhiteSpace(r.Rule.Kapitel) ? "" : $"{L.Get("MetaChapter")}: {r.Rule.Kapitel}",
                $"{L.Get("MetaProfile")}: {r.Rule.Profil}",
                $"{L.Get("MetaTarget")}: {ScanService.ZielLabel(r.Rule.Ziel)}",
                $"{L.Get("MetaValidFrom")}: {r.Rule.GiltAb}",
                string.IsNullOrWhiteSpace(r.ManualKind) ? "" : $"{L.Get("MetaReason")}: {ScanService.ManualKindLabel(r.ManualKind)}",
            }.Where(s => !string.IsNullOrEmpty(s))),
            Notiz = r.Rule.Notiz26H2 ?? "",
            NotizZeile = string.IsNullOrWhiteSpace(r.Rule.Notiz26H2) ? "" : $"{L.Get("Note26H2Prefix")}{r.Rule.Notiz26H2}",
            LabelDesc = L.Get("DetailDescription") + ": ",
            LabelActual = L.Get("DetailActual") + ": ",
            LabelExpected = "   " + L.Get("DetailExpected") + ": ",
            LabelFix = L.Get("DetailFix") + ": ",
            Description = r.Rule.Description,
            Actual = r.ActualValue ?? "–",
            Expected = r.ExpectedValue ?? "–",
            Fix = r.Rule.FixHint,
            Message = r.Message,
            FixButton = L.Get("FixButtonLabel"),
            GuideButton = L.Get("GuideButtonLabel"),
            FixVisible = RemediationRunner.CanAutoFix(r.Rule)
                && r.Status is CheckStatus.Failed or CheckStatus.Warning
                ? Visibility.Visible : Visibility.Collapsed,
            GuideVisible = r.Rule.Remediation is not null ? Visibility.Visible : Visibility.Collapsed,
            FixNote = r.Rule.Remediation?.RequiresReboot == true && r.Rule.Remediation.Mode == "auto"
                ? "⚠ " + L.Get("FixRebootNote") : "",
            FixNoteVisible = r.Rule.Remediation?.RequiresReboot == true && r.Rule.Remediation.Mode == "auto"
                ? Visibility.Visible : Visibility.Collapsed,
        };
    }

    private async void FixButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string ruleId }) return;
        var result = ScanService.Current.VisibleResults().FirstOrDefault(r => r.Rule.Id == ruleId);
        if (result?.Rule.Remediation is null) return;

        if (!CheckRunner.IsElevated())
        {
            var admin = new ContentDialog
            {
                Title = L.Get("FixAdminTitle"),
                Content = L.Get("FixAdminText"),
                PrimaryButtonText = L.Get("FixAdminOk"),
                CloseButtonText = L.Get("DialogCancel"),
                XamlRoot = XamlRoot,
            };
            if (await admin.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    CheckRunner.RelaunchAsAdmin();
                    // New admin instance starts: close this one so only one window stays open.
                    Application.Current.Exit();
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // User cancelled UAC – stay open.
                }
                catch { }
            }
            return;
        }

        var rem = result.Rule.Remediation!;
        var lines = L.F("FixConfirmText", result.Rule.Title,
            result.ActualValue ?? "–", result.ExpectedValue ?? "–")
            + $"\n\n{L.Get("FixRisk")}: {RiskLabel(rem.Risk)}";
        if (rem.RequiresReboot) lines += "\n⚠ " + L.Get("FixRebootNote");
        var confirm = new ContentDialog
        {
            Title = L.Get("FixConfirmTitle"),
            Content = new TextBlock { Text = lines, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = L.Get("FixApply"),
            CloseButtonText = L.Get("DialogCancel"),
            XamlRoot = XamlRoot,
        };
        if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;

        RemediationOutcome outcome;
        try
        {
            outcome = await ScanService.Current.ApplyFixAsync(ruleId);
        }
        catch (Exception ex)
        {
            outcome = new RemediationOutcome { Message = ex.Message };
        }

        var done = new ContentDialog
        {
            Title = result.Rule.Title,
            Content = new TextBlock
            {
                Text = outcome.Success
                    ? L.Get("FixSuccess") + (outcome.RequiresReboot ? "\n⚠ " + L.Get("FixRebootNote") : "")
                    : (outcome.Blocked ? L.F("FixBlocked", outcome.Message) : L.F("FixFailed", outcome.Message)),
                TextWrapping = TextWrapping.Wrap,
            },
            CloseButtonText = "OK",
            XamlRoot = XamlRoot,
        };
        await done.ShowAsync();
        Refresh();
    }

    private static string RiskLabel(string risk) => risk switch
    {
        "high" => L.Get("RiskHigh"),
        "medium" => L.Get("RiskMedium"),
        _ => L.Get("RiskLow"),
    };

    private async void GuideButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string ruleId }) return;
        var result = ScanService.Current.VisibleResults().FirstOrDefault(r => r.Rule.Id == ruleId);
        var rem = result?.Rule.Remediation;
        if (rem is null) return;

        var copyLabel = L.Get("CopyButtonLabel");
        var copiedNote = L.Get("CopiedNote");
        var status = new TextBlock
        {
            FontSize = 12,
            Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
        };
        var list = new StackPanel { Spacing = 8 };

        void AddHeader(string text)
        {
            list.Children.Add(new TextBlock
            {
                Text = text,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                FontSize = 15,
            });
        }

        void AddRow(string text, string? copy)
        {
            var grid = new Grid { ColumnSpacing = 8 };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var tb = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap };
            Grid.SetColumn(tb, 0);
            grid.Children.Add(tb);
            if (!string.IsNullOrWhiteSpace(copy))
            {
                var cmd = copy;
                var btn = new Button { Content = copyLabel, Tag = cmd, VerticalAlignment = VerticalAlignment.Top };
                Grid.SetColumn(btn, 1);
                btn.Click += (_, _) =>
                {
                    try
                    {
                        var pkg = new DataPackage();
                        pkg.SetText(cmd);
                        Clipboard.SetContent(pkg);
                        status.Text = copiedNote;
                    }
                    catch
                    {
                        status.Text = cmd;
                    }
                };
                grid.Children.Add(btn);
            }
            list.Children.Add(grid);
        }

        // Rows of (display text, copyable command or null).
        AddRow($"{L.Get("FixRisk")}: {RiskLabel(rem.Risk)}", null);
        if (rem.RequiresReboot) AddRow("⚠ " + L.Get("FixRebootNote"), null);

        // Variante A: grafische Oberfläche (GUI-Pfad + Schritte ohne Befehle).
        AddHeader(L.Get("GuideGuiHeader"));
        if (!string.IsNullOrWhiteSpace(rem.Gui)) AddRow("• " + rem.Gui, null);
        if (rem.Mode == "manual")
        {
            for (var i = 0; i < rem.Steps.Count; i++)
            {
                if (RemediationScript.TryExtractCommand(rem.Steps[i]) is null)
                    AddRow($"{i + 1}. {rem.Steps[i]}", null);
            }
        }

        // Variante B: Befehlszeile (jeder Befehl mit Kopieren-Button).
        AddHeader(L.Get("GuideCliHeader"));
        var cliRows = 0;
        if (rem.Mode == "manual")
        {
            for (var i = 0; i < rem.Steps.Count; i++)
            {
                var cmd = RemediationScript.TryExtractCommand(rem.Steps[i]);
                if (!string.IsNullOrWhiteSpace(cmd))
                {
                    AddRow($"{i + 1}. {rem.Steps[i]}", cmd);
                    cliRows++;
                }
            }
        }
        else
        {
            foreach (var a in rem.Actions)
            {
                string? copy = null;
                try { copy = RemediationScript.Apply(a); } catch { }
                AddRow("• " + RemediationScript.Describe(a), copy);
                if (!string.IsNullOrWhiteSpace(copy)) cliRows++;
            }
        }
        if (cliRows == 0) AddRow(L.Get("GuideNoCli"), null);
        if (rem.Mode == "auto") AddRow(L.Get("GuideVerify"), null);
        list.Children.Add(status);

        var dialog = new ContentDialog
        {
            Title = $"{L.Get("GuideTitle")}: {result!.Rule.Id}",
            Content = new ScrollViewer { MaxHeight = 480, Content = list },
            CloseButtonText = "OK",
            XamlRoot = XamlRoot,
        };
        await dialog.ShowAsync();
    }
}
