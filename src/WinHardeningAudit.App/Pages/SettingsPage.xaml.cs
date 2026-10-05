using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinHardeningAudit.Core.Engine;
using WinHardeningAudit_App.Services;

namespace WinHardeningAudit_App.Pages;

public sealed partial class SettingsPage : Page
{
    private bool _langInit;

    public SettingsPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        RefreshLanguage();
        RefreshExportFolder();
        RefreshVersion();
        _langInit = true;
    }

    private void RefreshLanguage()
    {
        LanguageBox.ItemsSource = new[] { L.Get("LanguageSystem"), L.Get("LanguageEnglish"), L.Get("LanguageGerman") };
        LanguageBox.SelectedItem = AppLanguage.GetSaved() switch
        {
            "en" => L.Get("LanguageEnglish"),
            "de" => L.Get("LanguageGerman"),
            _ => L.Get("LanguageSystem"),
        };
    }

    private void LanguageBox_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_langInit || LanguageBox.SelectedItem is not string s) return;
        var choice = s == L.Get("LanguageEnglish") ? "en" : s == L.Get("LanguageGerman") ? "de" : "system";
        AppLanguage.Save(choice);
        AppLanguage.Apply(choice);
    }

    private void RestartButton_Click(object sender, RoutedEventArgs e) => AppLanguage.Restart();

    private void RefreshExportFolder()
    {
        try { ExportFolderText.Text = ScanService.ExportFolder; }
        catch (Exception ex) { ExportFolderText.Text = L.F("ExportError", ex.Message); }
    }

    private void ExportFolderOpen_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = ScanService.ExportFolder,
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { ExportFolderText.Text = L.F("ExportError", ex.Message); }
    }

    private void ResetButton_Click(object sender, RoutedEventArgs e)
    {
        AppLanguage.Reset();
        RefreshLanguage();
        ResetResultText.Text = L.Get("ResetDone");
    }

    private void RefreshVersion()
    {
        var v = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = L.F("AboutVersion", v?.ToString() ?? "?");
        try
        {
            var rules = CheckRunner.LoadRulesFromDirectory(ScanService.Current.RulesDir);
            var l1 = rules.Count(r => r.Profil == "L1");
            var l2 = rules.Count(r => r.Profil == "L2");
            var ms = rules.Count(r => r.Profil == "MS");
            CisText.Text = L.F("AboutCisCounts", l1, l2);
            MsText.Text = L.F("AboutMsCounts", ms, rules.Count, rules.Select(r => r.Category).Distinct().Count());
        }
        catch
        {
            CisText.Text = L.Get("AboutRulesError");
            MsText.Text = "";
        }
    }
}
