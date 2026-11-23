namespace FileAccessMonitor.Services;

// API and command-line messages of backup and restore (see Messages)
public static class MessagesBackup
{
    public static readonly IReadOnlyDictionary<string, string> En = new Dictionary<string, string>
    {
        ["backup.noData"] = "The data folder {0} does not exist.",
        ["backup.badTarget"] = "Backups cannot be put inside the data folder other than in its backups folder ({0}).",
        ["backup.damaged"] = "The backup is damaged or incomplete; these files are missing or changed: {0}",
        ["backup.inUse"] = "The database is in use ({0}). Stop the FileAccessMonitor services first.",
        ["backup.newer"] = "The backup holds data of version {0}, newer than this program ({1}). Install version {0} or later first, or restore with --force.",
        ["backup.notFound"] = "There is no backup named \"{0}\".",
        ["backup.deleted"] = "Backup {0} deleted.",
        ["backup.folderNotAbsolute"] = "Enter the full path of the folder, for example D:\\Backups\\FileAccessMonitor or \\\\server\\share\\fam ({0}).",
        ["backup.folderInData"] = "The backup folder must be outside the data folder ({0}). Leave it empty to use the data folder's own backups folder.",
        ["backup.folderNotWritable"] = "The service cannot create folders in {0}. Allow the service account to modify it (Windows: NT SERVICE\\FileAccessMonitor; a share: the monitoring server's computer account; Linux: fileaccessmonitor).",
        ["backup.cannotProtect"] = "The permissions of the backup cannot be set in {0}, so the keys would be readable there. Use a folder on an NTFS drive or a share that keeps permissions.",
    };

    public static readonly IReadOnlyDictionary<string, string> Ja = new Dictionary<string, string>
    {
        ["backup.noData"] = "データフォルダ {0} がありません。",
        ["backup.badTarget"] = "データフォルダの中には、backups フォルダ以外にバックアップを置けません（{0}）。",
        ["backup.damaged"] = "バックアップが壊れているか、不完全です。次のファイルがないか、変更されています: {0}",
        ["backup.inUse"] = "データベースが使用中です（{0}）。先に FileAccessMonitor のサービスを停止してください。",
        ["backup.newer"] = "このバックアップは、このプログラム（{1}）より新しいバージョン {0} のデータです。先にバージョン {0} 以降をインストールするか、--force を付けて復元してください。",
        ["backup.notFound"] = "「{0}」という名前のバックアップはありません。",
        ["backup.deleted"] = "バックアップ {0} を削除しました。",
        ["backup.folderNotAbsolute"] = "フォルダはフルパスで入力してください。例: D:\\Backups\\FileAccessMonitor、\\\\server\\share\\fam（{0}）",
        ["backup.folderInData"] = "バックアップ先は、データフォルダの外にしてください（{0}）。データフォルダの backups フォルダを使う場合は空欄にします。",
        ["backup.folderNotWritable"] = "サービスが {0} にフォルダを作れません。サービスのアカウントに変更の権限を付けてください（Windows: NT SERVICE\\FileAccessMonitor、共有フォルダ: 監視サーバーのコンピューターアカウント、Linux: fileaccessmonitor）。",
        ["backup.cannotProtect"] = "{0} ではバックアップの権限を設定できないため、鍵が読める状態になります。NTFS のドライブ、または権限を保持できる共有フォルダを指定してください。",
    };
}
