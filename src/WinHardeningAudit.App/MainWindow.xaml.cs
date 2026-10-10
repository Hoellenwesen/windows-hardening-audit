using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinHardeningAudit_App.Pages;
using WinHardeningAudit_App.Services;
using WinHardeningAudit.Core.Engine;

namespace WinHardeningAudit_App;

public sealed partial class MainWindow : Window
{
    public static new MainWindow? Current { get; private set; }

    public MainWindow()
    {
        InitializeComponent();
        Current = this;

        BuildCategoryNav();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        AppWindow.SetIcon("Assets/AppIcon.ico");

        // Compact startup size without wasted space; minimum size for tables.
        AppWindow.Resize(new Windows.Graphics.SizeInt32(1280, 860));
        var displayArea = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary);
        var centered = new Windows.Graphics.PointInt32(
            displayArea.WorkArea.X + (displayArea.WorkArea.Width - 1280) / 2,
            displayArea.WorkArea.Y + (displayArea.WorkArea.Height - 860) / 2);
        AppWindow.Move(centered);
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.PreferredMinimumWidth = 1100;
            presenter.PreferredMinimumHeight = 720;
        }

        AdminBar.IsOpen = !CheckRunner.IsElevated();
        NavFrame.Navigate(typeof(DashboardPage));
    }

    private void ElevateButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            CheckRunner.RelaunchAsAdmin();
            // New admin instance starts: close this one so only one instance stays open.
            Microsoft.UI.Xaml.Application.Current.Exit();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User cancelled UAC – just do nothing.
        }
        catch (Exception ex)
        {
            AdminBar.Message = L.F("AdminRestartFailed", ex.Message);
            AdminBar.Severity = InfoBarSeverity.Error;
        }
    }

    private static readonly Dictionary<string, string> _categoryGlyphs = new(StringComparer.Ordinal)
    {
        ["accounts-uac"] = "\uE77B",
        ["defender-malware"] = "\uE83D",
        ["bitlocker-encryption"] = "\uE72E",
        ["firewall-network"] = "\uE969",
        ["secureboot-vbs"] = "\uE7AE",
        ["updates-maintenance"] = "\uE777",
        ["audit-logging"] = "\uE9D9",
        ["system-hardening"] = "\uE724",
        ["browser-edge"] = "\uE774",
        ["user-rights"] = "\uE8D4",
        ["services"] = "\uE770",
    };

    private void BuildCategoryNav()
    {
        // MenuItems: [0]=dashboard, [1]=separator, then categories, separator, export, about.
        var insertAt = 2;
        foreach (var key in ScanService.Categories)
        {
            var item = new NavigationViewItem
            {
                Content = ScanService.CategoryLabel(key),
                Tag = "cat:" + key,
                Icon = new FontIcon { Glyph = _categoryGlyphs.TryGetValue(key, out var g) ? g : "\uE724" },
            };
            NavView.MenuItems.Insert(insertAt++, item);
        }
    }

    private void TitleBar_PaneToggleRequested(TitleBar sender, object args)
    {
        NavView.IsPaneOpen = !NavView.IsPaneOpen;
    }

    private void TitleBar_BackRequested(TitleBar sender, object args)
    {
        if (NavFrame.CanGoBack) NavFrame.GoBack();
    }

    public void NavigateToCategory(string category)
    {
        foreach (var item in NavView.MenuItems.OfType<NavigationViewItem>())
        {
            if (item.Tag is string tag && tag == "cat:" + category)
            {
                NavView.SelectedItem = item;
                break;
            }
        }
        NavFrame.Navigate(typeof(CategoryPage), category);
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item && item.Tag is string tag)
        {
            if (tag == "dash") NavFrame.Navigate(typeof(DashboardPage));
            else if (tag == "export") NavFrame.Navigate(typeof(ExportPage));
            else if (tag == "about") NavFrame.Navigate(typeof(AboutPage));
            else if (tag == "settings") NavFrame.Navigate(typeof(SettingsPage));
            else if (tag.StartsWith("cat:")) NavFrame.Navigate(typeof(CategoryPage), tag[4..]);
        }
    }
}
