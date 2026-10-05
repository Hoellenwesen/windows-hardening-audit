using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
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
        };
    }
}
