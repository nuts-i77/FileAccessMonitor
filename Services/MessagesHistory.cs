namespace FileAccessMonitor.Services;

// API messages of the history feature (see Messages)
public static class MessagesHistory
{
    public static readonly IReadOnlyDictionary<string, string> En = new Dictionary<string, string>
    {
        ["hist.pathRequired"] = "The path parameter is required.",
        ["hist.none"] = "There are no records of this file or folder.",
        ["hist.csv.step"] = "Step",
        ["hist.csv.via"] = "Via folder",
        ["hist.csv.count"] = "Count (period)",
        ["hist.kind.create"] = "Created",
        ["hist.kind.read"] = "Read",
        ["hist.kind.write"] = "Written",
        ["hist.kind.rename"] = "Renamed",
        ["hist.kind.move"] = "Moved",
        ["hist.kind.permission"] = "Permissions changed",
        ["hist.csv.permissionAtCreation"] = "Permission (set at creation)",
        ["hist.kind.delete"] = "Deleted",
        ["hist.kind.denied"] = "Refused",
        ["hist.gap.outOfScope"] = "Steps outside your viewing scope are hidden",
        ["hist.gap.unknownDestination"] = "Destination unknown (no record of where it went)",
        ["hist.gap.unknownOrigin"] = "Origin unknown (recording started after the file was created)",
    };

    public static readonly IReadOnlyDictionary<string, string> Ja = new Dictionary<string, string>
    {
        ["hist.pathRequired"] = "path パラメーターが必要です。",
        ["hist.none"] = "このファイルまたはフォルダーの記録はありません。",
        ["hist.csv.step"] = "操作",
        ["hist.csv.via"] = "経由したフォルダー",
        ["hist.csv.count"] = "回数 (期間)",
        ["hist.kind.create"] = "作成",
        ["hist.kind.read"] = "読み取り",
        ["hist.kind.write"] = "書き込み",
        ["hist.kind.rename"] = "名前変更",
        ["hist.kind.move"] = "移動",
        ["hist.kind.permission"] = "権限変更",
        ["hist.csv.permissionAtCreation"] = "権限変更（作成時の設定）",
        ["hist.kind.delete"] = "削除",
        ["hist.kind.denied"] = "拒否",
        ["hist.gap.outOfScope"] = "閲覧範囲外の操作は表示されません",
        ["hist.gap.unknownDestination"] = "移動先は不明です (移動先の記録がありません)",
        ["hist.gap.unknownOrigin"] = "出所は不明です (ファイルの作成後に記録が始まりました)",
    };
}
