namespace FileAccessMonitor.Services;

// API messages of the integrity feature (see Messages)
public static class MessagesIntegrity
{
    public static readonly IReadOnlyDictionary<string, string> En = new Dictionary<string, string>
    {
        ["integrity.noKey"] = "The tamper-detection key (chain.key) cannot be read.",
        ["integrity.runNotFound"] = "No such verification.",
        ["integrity.nothingToAccept"] = "There is no finding to accept.",
        ["integrity.accepted"] = "The {0} chain starts again from its current state; its findings are accepted.",
        ["integrity.anchorInvalid"] = "This is not an anchor. Paste a FAM-ANCHOR line or the contents of an anchor file.",
        ["integrity.alertTitle"] = "Tamper detection: the record chain is broken ({0}: {1})",
        ["integrity.alertBody"] = "Records may have been changed, deleted or added outside this program.\nChain: {0}, finding: {1}, from #{2}, between {3}.\nServer: {4}\nOpen findings: {5}\nOpen Settings > Tamper detection to see where.",
        ["integrity.anchorTitle"] = "Daily tamper-detection anchor",
        ["integrity.anchorBody"] = "Keep this line outside this machine. Later, Settings > Tamper detection > Check an anchor compares it with the stored records.\n{0}",
    };

    public static readonly IReadOnlyDictionary<string, string> Ja = new Dictionary<string, string>
    {
        ["integrity.noKey"] = "改ざん検知の鍵（chain.key）を読み込めません。",
        ["integrity.runNotFound"] = "該当する検証が見つかりません。",
        ["integrity.nothingToAccept"] = "承認する検出結果がありません。",
        ["integrity.accepted"] = "{0} のチェーンを現在の状態から再開し、検出結果を承認しました。",
        ["integrity.anchorInvalid"] = "アンカーではありません。FAM-ANCHOR の行、またはアンカーファイルの内容を貼り付けてください。",
        ["integrity.alertTitle"] = "改ざん検知: 記録のチェーンが破損しています（{0}: {1}）",
        ["integrity.alertBody"] = "記録が本プログラム以外で変更・削除・追加された可能性があります。\nチェーン: {0}、検出: {1}、#{2} から、{3} の間。\nサーバー: {4}\n未承認の検出結果: {5} 件\n場所は、［設定］>［改ざん検知］で確認してください。",
        ["integrity.anchorTitle"] = "改ざん検知の日次アンカー",
        ["integrity.anchorBody"] = "この行を、このマシンの外に保管してください。後で、［設定］>［改ざん検知］>［アンカーを照合］で、保存された記録と比較できます。\n{0}",
    };
}
