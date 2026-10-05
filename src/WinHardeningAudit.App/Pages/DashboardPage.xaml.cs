using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinHardeningAudit.Core.Models;
using WinHardeningAudit_App.Services;

namespace WinHardeningAudit_App.Pages;

public sealed partial class DashboardPage : Page
{
    private sealed record CategoryCard(string Key, string Name, string Counts);
    private sealed record SearchHit(string Category, string Title, string Detail);

    private bool _init;
    private readonly EventHandler _changedHandler;
    private CancellationTokenSource? _scanCts;

    public DashboardPage()
    {
        InitializeComponent();
        _changedHandler = (_, _) => DispatcherQueue.TryEnqueue(Refresh);
        ScanService.Current.Changed += _changedHandler;
        ProfileBox.ItemsSource = ScanService.Profiles.Select(ScanService.ProfileLabel).ToList();
        TargetBox.ItemsSource = ScanService.Targets.Select(ScanService.TargetLabel).ToList();
        ProfileBox.SelectedItem = ScanService.ProfileLabel(ScanService.Current.Profile);
        TargetBox.SelectedItem = ScanService.TargetLabel(ScanService.Current.Target);
        _init = true;
        Refresh();
        _ = AutoScanIfNeeded();
    }

    private void ProfileBox_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_init || ProfileBox.SelectedItem is not string s) return;
        ScanService.Current.Profile = ScanService.ProfileFromLabel(s);
    }

    private void TargetBox_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_init || TargetBox.SelectedItem is not string s) return;
        ScanService.Current.Target = ScanService.TargetFromLabel(s);
    }

    private async Task AutoScanIfNeeded()
    {
        if (ScanService.Current.Report is null && !ScanService.Current.IsScanning)
            await RunScan();
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e) => await RunScan();

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private async Task RunScan()
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        ScanButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        ScanProgress.IsActive = true;
        StatusLine.Text = L.Get("StatusScanning");
        try
        {
            await ScanService.Current.RunAsync(_scanCts.Token);
            StatusLine.Text = L.Get("StatusScanDone");
        }
        catch (OperationCanceledException)
        {
            StatusLine.Text = L.Get("StatusScanCancelled");
        }
        catch (Exception ex)
        {
            StatusLine.Text = L.F("StatusScanFailed", ex.Message);
        }
        finally
        {
            ScanProgress.IsActive = false;
            ScanButton.IsEnabled = true;
            CancelButton.IsEnabled = false;
            Refresh();
        }
    }

    private void Refresh()
    {
        var svc = ScanService.Current;
        ScanProgress.IsActive = svc.IsScanning;
        ScanButton.IsEnabled = !svc.IsScanning;
        CancelButton.IsEnabled = svc.IsScanning;
        if ((ProfileBox.SelectedItem as string) != ScanService.ProfileLabel(svc.Profile))
            ProfileBox.SelectedItem = ScanService.ProfileLabel(svc.Profile);
        if ((TargetBox.SelectedItem as string) != ScanService.TargetLabel(svc.Target))
            TargetBox.SelectedItem = ScanService.TargetLabel(svc.Target);
        L2Banner.IsOpen = svc.ShowL2Banner;
        L2Banner.Message = L.F("L2BannerMessage", svc.L2RuleCount) + (svc.L2RuleCount == 0 ? " " + L.Get("L2BannerL1Note") : "");
        var r = svc.Report;
        if (r is null)
        {
            StatusLine.Text = svc.IsScanning ? L.Get("StatusScanning") : L.F("StatusNoScan", svc.MachineInfo);
            return;
        }
        var (total, passed, failed, crit, high) = svc.FilteredSummary();
        ScoreText.Text = $"{svc.FilteredScore()}%";
        PassFailText.Text = $"{passed} / {failed}";
        CritText.Text = crit.ToString();
        HighText.Text = high.ToString();
        StatusLine.Text = L.F("StatusLine", r.MachineName, svc.MachineInfo,
            r.IsElevated ? L.Get("YesNoTrue") : L.Get("YesNoFalse"),
            r.Timestamp.ToString("g", System.Globalization.CultureInfo.CurrentCulture), ScanService.ProfileLabel(svc.Profile),
            ScanService.TargetLabel(svc.Target), total, r.Summary.Total);
        RefreshGlobalSearch();

        TopRisksList.ItemsSource = svc.TopRisks(5).Select(x => new
        {
            Title = $"[{ScanService.SeverityLabel(x.Rule.Severity)}] {x.Rule.Title}",
            Detail = $"{x.Rule.Id} · {ScanService.CategoryLabel(x.Rule.Category)} · {L.Get("IstLabel")}: {x.ActualValue ?? "–"} · {L.Get("SollLabel")}: {x.ExpectedValue ?? "–"} · {x.Rule.FixHint}"
        }).ToList();

        CategoryGrid.ItemsSource = ScanService.Categories.Select(c =>
        {
            var (t, p, f) = svc.CategoryCounts(c);
            return new CategoryCard(c, ScanService.CategoryLabel(c), t == 0 ? L.Get("CountsNone") : L.F("CountsFormat", p, t, f));
        }).ToList();
    }

    private void GlobalSearch_Changed(object sender, TextChangedEventArgs e) => RefreshGlobalSearch();

    private void RefreshGlobalSearch()
    {
        var q = GlobalSearchBox?.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(q) || q.Length < 2)
        {
            GlobalSearchList.ItemsSource = null;
            return;
        }
        GlobalSearchList.ItemsSource = ScanService.Current.SearchAll(q, 30).Select(x => new SearchHit(
            x.Rule.Category,
            $"[{ScanService.SeverityLabel(x.Rule.Severity)}] {x.Rule.Title} ({x.Rule.Id})",
            $"{ScanService.CategoryLabel(x.Rule.Category)} · {L.Get("IstLabel")}: {x.ActualValue ?? "–"} · {L.Get("SollLabel")}: {x.ExpectedValue ?? "–"}")).ToList();
    }

    private void GlobalSearch_ItemClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is SearchHit hit && !string.IsNullOrEmpty(hit.Category))
            WinHardeningAudit_App.MainWindow.Current?.NavigateToCategory(hit.Category);
    }

    private void CategoryGrid_ItemClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is CategoryCard card && !string.IsNullOrEmpty(card.Key))
            WinHardeningAudit_App.MainWindow.Current?.NavigateToCategory(card.Key);
    }

    protected override void OnNavigatedTo(NavigationEventArgs e) => Refresh();

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        ScanService.Current.Changed -= _changedHandler;
    }
}
