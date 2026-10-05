using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinHardeningAudit_App.Services;

namespace WinHardeningAudit_App.Pages;

public sealed partial class ExportPage : Page
{
    private readonly EventHandler _changedHandler;

    public ExportPage()
    {
        InitializeComponent();
        _changedHandler = (_, _) => DispatcherQueue.TryEnqueue(RefreshFilter);
        ScanService.Current.Changed += _changedHandler;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e) => RefreshFilter();

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        ScanService.Current.Changed -= _changedHandler;
    }

    private void RefreshFilter()
    {
        var svc = ScanService.Current;
        FilterText.Text = svc.Report is null
            ? L.Get("ExportNoScan")
            : L.F("ExportFilter", ScanService.ProfileLabel(svc.Profile), ScanService.TargetLabel(svc.Target));
    }

    private void Html_Click(object sender, RoutedEventArgs e)
    {
        try { ResultText.Text = L.F("ExportSaved", ScanService.Current.ExportHtml()); }
        catch (Exception ex) { ResultText.Text = L.F("ExportError", ex.Message); }
    }

    private void Json_Click(object sender, RoutedEventArgs e)
    {
        try { ResultText.Text = L.F("ExportSaved", ScanService.Current.ExportJson()); }
        catch (Exception ex) { ResultText.Text = L.F("ExportError", ex.Message); }
    }

    private void Csv_Click(object sender, RoutedEventArgs e)
    {
        try { ResultText.Text = L.F("ExportSaved", ScanService.Current.ExportCsv()); }
        catch (Exception ex) { ResultText.Text = L.F("ExportError", ex.Message); }
    }

    private void FullHtml_Click(object sender, RoutedEventArgs e)
    {
        try { ResultText.Text = L.F("ExportSaved", ScanService.Current.ExportFullHtml()); }
        catch (Exception ex) { ResultText.Text = L.F("ExportError", ex.Message); }
    }
}
