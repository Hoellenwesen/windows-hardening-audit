using WinAppResources = Microsoft.Windows.ApplicationModel.Resources;

namespace WinHardeningAudit_App.Services;

public static class L
{
    private static readonly WinAppResources.ResourceLoader _loader = new();

    public static string Get(string key)
    {
        try
        {
            var s = _loader.GetString(key);
            return string.IsNullOrEmpty(s) ? key : s;
        }
        catch
        {
            return key;
        }
    }

    public static string F(string key, params object[] args)
    {
        try { return string.Format(Get(key), args); }
        catch { return Get(key); }
    }
}

/// <summary>
/// UI language handling: system default plus an optional manual override
/// (persisted in LocalSettings, applied via PrimaryLanguageOverride).
/// Also wires the Core engine strings to the active language.
/// </summary>
public static class AppLanguage
{
    private const string SettingKey = "language"; // "system" | "en" | "de"

    /// <summary>Effective engine/UI language: "de" or "en".</summary>
    public static string Current { get; private set; } = "de";

    private static string SettingsPath()
    {
        // File-based (not ApplicationData): the portable package runs unpackaged
        // and therefore has no package identity for ApplicationData.
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WinHardeningAudit");
        return Path.Combine(dir, "settings.json");
    }

    public static string GetSaved()
    {
        try
        {
            var p = SettingsPath();
            if (!File.Exists(p)) return "system";
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(p));
            if (doc.RootElement.TryGetProperty(SettingKey, out var v))
            {
                var s = v.GetString();
                return s is "en" or "de" or "system" ? s : "system";
            }
            return "system";
        }
        catch { return "system"; }
    }

    public static void Save(string choice)
    {
        try
        {
            var p = SettingsPath();
            Directory.CreateDirectory(Path.GetDirectoryName(p)!);
            // Manual JSON: choice comes from a fixed set, no escaping needed.
            // (Avoids System.Text.Json trimming warning IL2026 for two strings.)
            File.WriteAllText(p, "{\"language\":\"" + choice + "\"}");
        }
        catch { }
    }

    public static void ApplySaved() => Apply(GetSaved());

    /// <summary>Deletes the persisted choice and reverts to the system language.</summary>
    public static void Reset()
    {
        try { File.Delete(SettingsPath()); }
        catch { }
        Apply("system");
    }

    public static void Apply(string choice)
    {
        if (choice is "en" or "de")
        {
            try
            {
                Microsoft.Windows.Globalization.ApplicationLanguages.PrimaryLanguageOverride =
                    choice == "en" ? "en-US" : "de-DE";
            }
            catch
            {
                // Override not accepted (e.g. missing language pack): fall back to system language.
                choice = "system";
            }
        }
        else
        {
            // Default = system language. Never touch the override with an empty
            // string here: MRTCore rejects "" with E_INVALIDARG in unpackaged apps.
            // A null assignment clears a previously set override; if that fails,
            // startup must still continue (worst case: previous override stays).
            try { Microsoft.Windows.Globalization.ApplicationLanguages.PrimaryLanguageOverride = null!; }
            catch { }
        }

        var lang = choice == "system" ? EffectiveSystemLanguage() : choice;
        Current = lang;
        WinHardeningAudit.Core.Engine.CoreStrings.Language = lang;
        if (lang == "de")
        {
            WinHardeningAudit.Core.Engine.CoreStrings.Override = key =>
            {
                var res = "Core" + key;
                var s = L.Get(res);
                return s == res ? null : s;
            };
        }
        else
        {
            WinHardeningAudit.Core.Engine.CoreStrings.Override = null;
        }
    }

    private static string EffectiveSystemLanguage()
    {
        try
        {
            var top = Microsoft.Windows.Globalization.ApplicationLanguages.Languages.FirstOrDefault() ?? "";
            return top.StartsWith("de", StringComparison.OrdinalIgnoreCase) ? "de" : "en";
        }
        catch { return "en"; }
    }

    /// <summary>Restarts the app (e.g. to apply a language change).</summary>
    public static void Restart()
    {
        try
        {
            var exe = Environment.ProcessPath
                ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (exe is not null)
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = exe,
                    UseShellExecute = true,
                });
            }
        }
        catch { }
        finally
        {
            try { Microsoft.UI.Xaml.Application.Current.Exit(); } catch { }
        }
    }
}
