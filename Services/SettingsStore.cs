using System.Text.Json;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// Single place that reads and writes settings.json. Each writer changes only its own
// keys, so saving one setting (e.g. retention days) never drops another (e.g. monitored paths).
public static class SettingsStore
{
    public static readonly string DefaultPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FileAccessMonitor", "settings.json");

    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    public static JsonObject Load() => Load(DefaultPath);

    public static void Update(Action<JsonObject> mutate) => Update(DefaultPath, mutate);

    internal static JsonObject Load(string path)
    {
        lock (Gate)
        {
            try
            {
                if (File.Exists(path) && JsonNode.Parse(File.ReadAllText(path)) is JsonObject root)
                    return root;
            }
            catch (JsonException) { }
            return new JsonObject();
        }
    }

    internal static void Update(string path, Action<JsonObject> mutate)
    {
        lock (Gate)
        {
            var root = Load(path);
            mutate(root);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            // Write to a temp file first so a crash never leaves a truncated settings.json
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, root.ToJsonString(WriteOptions));
            File.Move(tmp, path, overwrite: true);
        }
    }
}
