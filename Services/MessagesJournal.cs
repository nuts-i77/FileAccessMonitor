namespace FileAccessMonitor.Services;

// API messages of turning on a drive's change journal from Settings → Monitored folders (see Messages)
public static class MessagesJournal
{
    public static readonly IReadOnlyDictionary<string, string> En = new Dictionary<string, string>
    {
        ["journal.created"] = "The change journal of {0} is on (up to 32 MB). Creations and new names are recorded from now on.",
        ["journal.exists"] = "{0} already has a change journal. It was left as it is.",
        ["journal.notOff"] = "The change journal can be turned on only for a drive shown without one.",
        ["journal.unknown"] = "The state of the change journal of {0} is not known yet. Try again in a minute; an agent needs version 1.13.1 or later.",
        ["journal.notWindows"] = "Only Windows drives have a change journal.",
        ["journal.unsupported"] = "{0} is {1}, which cannot have a change journal (only NTFS and ReFS can).",
        ["journal.failed"] = "The change journal of {0} could not be turned on ({1}). Turn it on on the server with: fsutil usn createjournal m=33554432 a=8388608 {0}",
    };

    public static readonly IReadOnlyDictionary<string, string> Ja = new Dictionary<string, string>
    {
        ["journal.created"] = "{0} の変更ジャーナルを有効にしました（最大 32 MB）。これから、作成と名前変更後の名前も記録します。",
        ["journal.exists"] = "{0} には、すでに変更ジャーナルがあります。変更はしていません。",
        ["journal.notOff"] = "変更ジャーナルを有効にできるのは、ジャーナルがないと表示されているドライブだけです。",
        ["journal.unknown"] = "{0} の変更ジャーナルの状態がまだ分かりません。1 分ほどしてから、もう一度試してください（エージェントの場合は 1.13.1 以降が必要です）。",
        ["journal.notWindows"] = "変更ジャーナルがあるのは、Windows のドライブだけです。",
        ["journal.unsupported"] = "{0} は {1} のため、変更ジャーナルを持てません（持てるのは NTFS と ReFS だけです）。",
        ["journal.failed"] = "{0} の変更ジャーナルを有効にできませんでした（{1}）。サーバーで次のコマンドを実行して有効にしてください: fsutil usn createjournal m=33554432 a=8388608 {0}",
    };
}
