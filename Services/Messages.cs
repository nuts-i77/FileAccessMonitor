using System.Globalization;
using Microsoft.AspNetCore.Identity;

namespace FileAccessMonitor.Services;

// API response messages. The language follows CurrentUICulture, which
// UseRequestLocalization sets from the Accept-Language header sent by the web GUI.
public static class Messages
{
    public static readonly IReadOnlyDictionary<string, string> En = new Dictionary<string, string>
    {
        ["auth.invalid"] = "Incorrect user name or password.",
        ["auth.lockedOut"] = "This account is temporarily locked after repeated failed sign-ins. Try again later.",
        ["password.changed"] = "Password changed.",
        ["password.required"] = "Enter a password.",
        ["password.bothRequired"] = "Enter the current and new passwords.",
        ["password.reset"] = "Password reset.",
        ["retention.invalidDays"] = "Retention days must be 0 or greater (0 = keep forever).",
        ["retention.forever"] = "keep forever",
        ["retention.days"] = "keep for {0} days",
        ["retention.updated"] = "Retention policy updated: {0}",
        ["retention.notSet"] = "No retention policy is set (records are kept forever). Set the retention days first.",
        ["retention.deleted"] = "Deleted {0:N0} records.",
        ["path.required"] = "Enter a path.",
        ["path.paramRequired"] = "The path parameter is required.",
        ["path.notFound"] = "Folder not found: {0}",
        ["path.duplicate"] = "This folder is already monitored.",
        ["path.notMonitored"] = "The specified path is not monitored.",
        ["path.added"] = "Added. SACL applied to {0} items.",
        ["path.removedSacl"] = "Removed from monitoring and removed SACL from {0} items.",
        ["path.removed"] = "Removed from monitoring. (SACL entries were left in place.)",
        ["path.saclApplied"] = "SACL applied to {0} items.",
        ["local.notCollecting"] = "This server does not record its own accesses (monitoring only). Select an agent server.",
        ["path.addedSamba"] = "Added. Samba auditing is on for {0} share(s); accesses are recorded from new connections to the share.",
        ["path.removedSaclSamba"] = "Removed from monitoring and turned Samba auditing off for {0} share(s).",
        ["path.saclAppliedSamba"] = "Samba auditing is on for {0} share(s).",
        ["path.eventTypeRequired"] = "Select at least one access type.",
        ["user.bothRequired"] = "User name and password are required.",
        ["user.created"] = "User \"{0}\" created.",
        ["user.cannotDeleteSelf"] = "You cannot delete your own account.",
        ["user.notFound"] = "User not found.",
        ["user.deleted"] = "User \"{0}\" deleted.",
        ["user.cannotChangeOwnRole"] = "You cannot change your own role.",
        ["user.invalidRole"] = "Role must be Admin or Viewer.",
        ["user.roleChanged"] = "Role changed.",
        ["recording.saved"] = "Recording rules saved. They apply to new records.",
        ["recording.invalidMinutes"] = "Merge time must be between 0 and {0} minutes.",
        ["recording.tooMany"] = "Too many entries, or an entry is too long (up to 200 entries of 260 characters each).",
        ["agents.badCode"] = "The registration code is wrong, already used, or expired. Issue a new one on the monitoring server.",
        ["agents.noEndpoint"] = "The agent port is not available (its certificate could not be created). Check the service log.",
        ["agents.portOff"] = "The agent port is turned off (\"Agents\": { \"Enabled\": false } in settings.json). Remove that setting and restart the service to register agents.",
        ["agents.badUrl"] = "Enter an https:// address.",
        ["agents.notFound"] = "Agent not found.",
        ["agents.isDisabled"] = "The agent \"{0}\" is disabled. Enable it first.",
        ["agents.noAnswer"] = "The agent \"{0}\" did not respond. Check that it is online (Settings > Agents).",
        ["agents.jobFailed"] = "The agent \"{0}\" reported an error: {1}",
        ["agents.disabled"] = "Agent \"{0}\" disabled. Its records are no longer accepted.",
        ["agents.enabled"] = "Agent \"{0}\" enabled.",
        ["agents.deleted"] = "Agent \"{0}\" removed. Its records are kept.",
        ["scope.saved"] = "Viewing scope saved.",
        ["scope.notMonitored"] = "Not inside a monitored folder: {0}",
        ["scope.invalidEmail"] = "The notification email address is not valid.",
        ["scope.emailNeedsPaths"] = "Set at least one folder to send notifications about.",
        ["scope.outside"] = "This folder is outside your viewing scope.",
        ["alerts.saved"] = "Notification settings saved.",
        ["alerts.invalid"] = "Thresholds must be 0 or greater, and the window and cooldown must be at least 1 minute.",
        ["alerts.noChannel"] = "Set a webhook URL or email settings first.",
        ["alerts.smtpHostRequired"] = "Enter the SMTP server to send email.",
        ["alerts.mailToRequired"] = "Enter at least one email recipient.",
        ["alerts.badProxy"] = "Enter the proxy as an address such as http://proxy.example.local:8080.",
        ["alerts.badWebhook"] = "Enter the webhook URL as an address starting with http:// or https://.",
        ["alerts.webhookForbidden"] = "The webhook cannot point to this machine (localhost, 127.x.x.x, ::1), a link-local address (169.254.x.x including the cloud metadata address, fe80::), or an unspecified or multicast address. Use the address of the chat service or of an internal server.",
        ["alerts.testSent"] = "Test notification sent.",
        ["alerts.testFailed"] = "Test notification failed: {0}",
        ["alert.deleteTitle"] = "Mass deletion detected",
        ["alert.writeTitle"] = "Mass file changes detected (possible ransomware)",
        ["alert.readTitle"] = "Mass file reads detected (possible data exfiltration)",
        ["alert.deniedTitle"] = "Many refused access attempts detected",
        ["alert.ransomwareTitle"] = "Ransomware-like behavior detected",
        ["alert.rule.extension"] = "Rule: many files renamed to the same new extension",
        ["alert.rule.burst"] = "Rule: mass writing together with mass renaming",
        ["alert.rule.note"] = "Rule: ransom note files created in several folders",
        ["alert.highPriority"] = "[HIGH PRIORITY]",
        ["alert.detail"] = "Detail: {0}",
        ["agentOffline.title"] = "An agent stopped reporting",
        ["agentOffline.body"] = "The agent \"{0}\" has not contacted the server for {1} minutes or more (last contact: {2}). Its service may be stopped, the server may be down, or the network may be disconnected. Records collected meanwhile are held by the agent and sent when it reconnects, unless the Security log there has overwritten them.",
        ["agentOnline.title"] = "An agent is reporting again",
        ["agentOnline.body"] = "The agent \"{0}\" is in touch with the monitoring server again.",
        ["agentOutboxFull.title"] = "An agent's send queue is full",
        ["agentOutboxFull.body"] = "The send queue of the agent \"{0}\" has reached its limit ({1}), so collection there is paused. The records stay in the file server's Security log (or journal) and are collected once the agent has delivered the waiting data. Check that this server is reachable from the agent. If the log wraps first, the oldest records are lost and a recording gap is reported.",
        ["gap.title"] = "Recording was interrupted",
        ["gap.cleared"] = "The Security log was cleared since the service last ran (cleared by: {0}). File accesses from before it was cleared may not have been recorded.",
        ["gap.overwritten"] = "{0:N0} Security log events (record {1}-{2}) were overwritten before they could be collected, for example while the service was stopped. File accesses in that period were not recorded. Increase the size of the Security log.",
        ["gap.journalRotated"] = "The journal on the Linux file server no longer had the entries from where the agent stopped (for example after a long stop, or a reboot when the journal is not kept on disk). File accesses in that period may not have been recorded.",
        ["gap.journalSuppressed"] = "journald dropped {0:N0} Samba audit lines on the Linux file server because they came too fast. Restart Samba there (systemctl restart smbd) so that the setting added by the agent's installer lifts the limit.",
        ["alert.user"] = "User: {0}",
        ["alert.count"] = "Files: {0} within {1} minutes",
        ["alert.period"] = "Period: {0} - {1}",
        ["alert.client"] = "Client: {0}",
        ["alert.server"] = "Server: {0}",
        ["alert.folders"] = "Main folders:",
        ["alert.samples"] = "Examples:",
        ["alert.testTitle"] = "Test notification",
        ["alert.testBody"] = "This is a test notification from FileAccessMonitor on {0}.",
        ["csv.time"] = "Date/Time",
        ["csv.timeUtc"] = "Date/Time (UTC)",
        ["csv.user"] = "User",
        ["csv.type"] = "Type",
        ["csv.kind"] = "File/Folder",
        ["csv.kindFile"] = "File",
        ["csv.kindFolder"] = "Folder",
        ["csv.fileName"] = "File Name",
        ["csv.folder"] = "Folder",
        ["csv.path"] = "Full Path",
        ["csv.ip"] = "Client IP",
        ["csv.machine"] = "Client Machine",
        ["csv.server"] = "File Server",
        ["csv.result"] = "Result",
        ["csv.resultOk"] = "Allowed",
        ["csv.permissionAtCreation"] = "Permission (set at creation)",
        ["csv.resultDenied"] = "Denied",
        ["csv.newPath"] = "New Path",
        ["csv.detail"] = "Detail",
    };

    public static readonly IReadOnlyDictionary<string, string> Ja = new Dictionary<string, string>
    {
        ["auth.invalid"] = "ユーザー名またはパスワードが正しくありません。",
        ["auth.lockedOut"] = "ログインの失敗が続いたため、アカウントが一時的にロックされています。しばらく待ってから再度実行してください。",
        ["password.changed"] = "パスワードを変更しました。",
        ["password.required"] = "パスワードを入力してください。",
        ["password.bothRequired"] = "現在のパスワードと新しいパスワードを入力してください。",
        ["password.reset"] = "パスワードをリセットしました。",
        ["retention.invalidDays"] = "保持日数は 0 以上を指定してください（0 = 無期限保持）。",
        ["retention.forever"] = "無期限保持",
        ["retention.days"] = "{0} 日間保持",
        ["retention.updated"] = "データ保持ポリシーを更新しました: {0}",
        ["retention.notSet"] = "データ保持ポリシーが未設定です（無期限保持）。先に保持日数を設定してください。",
        ["retention.deleted"] = "{0:N0} 件の記録を削除しました。",
        ["path.required"] = "パスを入力してください。",
        ["path.paramRequired"] = "path パラメーターは必須です。",
        ["path.notFound"] = "フォルダが見つかりません: {0}",
        ["path.duplicate"] = "このフォルダは、すでに監視フォルダに登録されています。",
        ["path.notMonitored"] = "指定されたパスは監視フォルダに登録されていません。",
        ["path.added"] = "追加しました。SACL を {0} 件に適用しました。",
        ["path.removedSacl"] = "監視フォルダから削除し、{0} 件から SACL を削除しました。",
        ["path.removed"] = "監視フォルダから削除しました（SACL は残っています）。",
        ["path.saclApplied"] = "SACL を {0} 件に適用しました。",
        ["local.notCollecting"] = "このサーバーは自身のアクセスを記録しません（監視専用）。エージェントのサーバーを選択してください。",
        ["path.addedSamba"] = "追加しました。{0} 個の共有で Samba の監査を有効にしました（共有への新しい接続から記録されます）。",
        ["path.removedSaclSamba"] = "監視フォルダから削除し、{0} 個の共有で Samba の監査を無効にしました。",
        ["path.saclAppliedSamba"] = "{0} 個の共有で Samba の監査を有効にしました。",
        ["path.eventTypeRequired"] = "1 つ以上の種別を選択してください。",
        ["user.bothRequired"] = "ユーザー名とパスワードは必須です。",
        ["user.created"] = "ユーザー「{0}」を作成しました。",
        ["user.cannotDeleteSelf"] = "自分自身のアカウントは削除できません。",
        ["user.notFound"] = "ユーザーが見つかりません。",
        ["user.deleted"] = "ユーザー「{0}」を削除しました。",
        ["user.cannotChangeOwnRole"] = "自分自身のロールは変更できません。",
        ["user.invalidRole"] = "ロールは Admin または Viewer を指定してください。",
        ["user.roleChanged"] = "ロールを変更しました。",
        ["recording.saved"] = "記録ルールを保存しました。以後に記録するアクセスから適用されます。",
        ["recording.invalidMinutes"] = "まとめる時間は 0～{0} 分の範囲で指定してください。",
        ["recording.tooMany"] = "項目数が上限を超えているか、長すぎる項目があります（最大 200 件、1 件あたり 260 文字）。",
        ["agents.badCode"] = "登録コードが正しくないか、使用済みまたは期限切れです。監視サーバーで新しいコードを発行してください。",
        ["agents.noEndpoint"] = "エージェント用のポートを使用できません（証明書を作成できませんでした）。サービスのログを確認してください。",
        ["agents.portOff"] = "エージェント用ポートが無効化されています（settings.json の \"Agents\": { \"Enabled\": false }）。エージェントを登録するには、この設定を削除してサービスを再起動してください。",
        ["agents.badUrl"] = "https:// で始まるアドレスを入力してください。",
        ["agents.notFound"] = "エージェントが見つかりません。",
        ["agents.isDisabled"] = "エージェント「{0}」は無効です。先に有効にしてください。",
        ["agents.noAnswer"] = "エージェント「{0}」から応答がありません。接続状態を確認してください（［設定］>［エージェント］）。",
        ["agents.jobFailed"] = "エージェント「{0}」でエラーが発生しました: {1}",
        ["agents.disabled"] = "エージェント「{0}」を無効にしました。記録は受信されません。",
        ["agents.enabled"] = "エージェント「{0}」を有効にしました。",
        ["agents.deleted"] = "エージェント「{0}」を削除しました。記録は保持されます。",
        ["scope.saved"] = "閲覧範囲を保存しました。",
        ["scope.notMonitored"] = "監視フォルダの配下ではありません: {0}",
        ["scope.invalidEmail"] = "通知先のメールアドレスが正しくありません。",
        ["scope.emailNeedsPaths"] = "通知を送信するには、フォルダを 1 つ以上指定してください。",
        ["scope.outside"] = "このフォルダは閲覧範囲外です。",
        ["alerts.saved"] = "通知設定を保存しました。",
        ["alerts.invalid"] = "しきい値は 0 以上、集計時間と再通知までの間隔は 1 分以上を指定してください。",
        ["alerts.noChannel"] = "先に Webhook URL またはメールの設定を行ってください。",
        ["alerts.smtpHostRequired"] = "メールを送信するには、SMTP サーバーを入力してください。",
        ["alerts.mailToRequired"] = "宛先を 1 件以上入力してください。",
        ["alerts.badProxy"] = "プロキシは、http://proxy.example.local:8080 の形式で入力してください。",
        ["alerts.badWebhook"] = "Webhook の URL は、http:// または https:// で始まるアドレスで入力してください。",
        ["alerts.webhookForbidden"] = "Webhook の宛先には、このマシン自身（localhost、127.x.x.x、::1）、リンクローカルアドレス（クラウドのメタデータ用アドレスを含む 169.254.x.x、fe80::）、未指定アドレス、マルチキャストアドレスは指定できません。チャットサービスまたは社内サーバーのアドレスを指定してください。",
        ["alerts.testSent"] = "テスト通知を送信しました。",
        ["alerts.testFailed"] = "テスト通知の送信に失敗しました: {0}",
        ["alert.deleteTitle"] = "大量削除を検知しました",
        ["alert.writeTitle"] = "大量のファイル変更を検知しました（ランサムウェアの疑い）",
        ["alert.readTitle"] = "大量のファイル読み取りを検知しました（情報持ち出しの疑い）",
        ["alert.deniedTitle"] = "アクセス拒否の多発を検知しました",
        ["alert.ransomwareTitle"] = "ランサムウェアに似た動作を検知しました",
        ["alert.rule.extension"] = "検知ルール: 多数のファイルを同じ新しい拡張子に名前変更",
        ["alert.rule.burst"] = "検知ルール: 大量の書き込みと大量の名前変更が同時に発生",
        ["alert.rule.note"] = "検知ルール: 複数のフォルダに脅迫文のファイルを作成",
        ["alert.highPriority"] = "【緊急】",
        ["alert.detail"] = "詳細: {0}",
        ["agentOffline.title"] = "エージェントからの接続が途絶えました",
        ["agentOffline.body"] = "エージェント「{0}」から {1} 分以上接続がありません（最終接続: {2}）。サービスの停止、サーバーの停止、ネットワークの切断などが考えられます。この間の記録はエージェントに保持され、再接続時に送信されます（対象サーバーの Security ログで上書きされていない場合）。",
        ["agentOnline.title"] = "エージェントからの接続が復旧しました",
        ["agentOnline.body"] = "エージェント「{0}」から再び接続がありました。",
        ["agentOutboxFull.title"] = "エージェントの送信待ちが満杯になりました",
        ["agentOutboxFull.body"] = "エージェント「{0}」の送信待ち領域が上限（{1}）に達したため、そのサーバーでの収集を一時停止しています。記録はファイルサーバーの Security ログ（またはジャーナル）に残り、エージェントが送信待ちのデータを送り終えた後に収集されます。エージェントからこのサーバーに接続できることを確認してください。それまでにログが上書きされた場合は、古い記録が失われ、記録の中断が通知されます。",
        ["gap.title"] = "記録が途切れました",
        ["gap.cleared"] = "サービスの前回の実行以降に、Security ログが消去されました（消去したユーザー: {0}）。消去前のファイルアクセスが記録されていない可能性があります。",
        ["gap.overwritten"] = "Security ログのイベント {0:N0} 件（レコード {1}～{2}）が、収集前に上書きされました（サービスの停止中など）。この間のファイルアクセスは記録されていません。Security ログのサイズの拡大を検討してください。",
        ["gap.journalRotated"] = "Linux ファイルサーバーのジャーナルに、エージェントが停止した時点以降の記録が残っていませんでした（長時間の停止、またはジャーナルをディスクに保存しない設定での再起動など）。この間のファイルアクセスが記録されていない可能性があります。",
        ["gap.journalSuppressed"] = "Linux ファイルサーバーの journald が、短時間に大量に出力された Samba の監査ログを {0:N0} 行破棄しました。エージェントのインストーラーが追加した設定を反映するため、そのサーバーで Samba を再起動してください（systemctl restart smbd）。",
        ["alert.user"] = "ユーザー: {0}",
        ["alert.count"] = "件数: {1} 分以内に {0} 件",
        ["alert.period"] = "期間: {0} ～ {1}",
        ["alert.client"] = "接続元: {0}",
        ["alert.server"] = "サーバー: {0}",
        ["alert.folders"] = "主なフォルダ:",
        ["alert.samples"] = "ファイルの例:",
        ["alert.testTitle"] = "テスト通知",
        ["alert.testBody"] = "{0} の FileAccessMonitor からのテスト通知です。",
        ["csv.time"] = "日時",
        ["csv.timeUtc"] = "日時（UTC）",
        ["csv.user"] = "ユーザー",
        ["csv.type"] = "種別",
        ["csv.kind"] = "ファイル/フォルダ",
        ["csv.kindFile"] = "ファイル",
        ["csv.kindFolder"] = "フォルダ",
        ["csv.fileName"] = "ファイル名",
        ["csv.folder"] = "フォルダ",
        ["csv.path"] = "フルパス",
        ["csv.ip"] = "接続元 IP",
        ["csv.machine"] = "接続元端末",
        ["csv.server"] = "ファイルサーバー",
        ["csv.result"] = "結果",
        ["csv.resultOk"] = "許可",
        ["csv.permissionAtCreation"] = "権限変更（作成時の設定）",
        ["csv.resultDenied"] = "拒否",
        ["csv.newPath"] = "変更後のパス",
        ["csv.detail"] = "詳細",
    };

    public static bool IsJapanese => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ja";

    // These tables plus one per feature (MessagesPermissions, ...), each with its own key prefix
    private static readonly Lazy<IReadOnlyDictionary<string, string>> AllEnLazy = new(() => Merge(
        En, MessagesPermissions.En, MessagesHistory.En, MessagesReports.En, MessagesIntegrity.En));
    private static readonly Lazy<IReadOnlyDictionary<string, string>> AllJaLazy = new(() => Merge(
        Ja, MessagesPermissions.Ja, MessagesHistory.Ja, MessagesReports.Ja, MessagesIntegrity.Ja));
    public static IReadOnlyDictionary<string, string> AllEn => AllEnLazy.Value;
    public static IReadOnlyDictionary<string, string> AllJa => AllJaLazy.Value;

    private static Dictionary<string, string> Merge(params IReadOnlyDictionary<string, string>[] tables)
    {
        var all = new Dictionary<string, string>();
        foreach (var table in tables)
            foreach (var (key, value) in table) all.Add(key, value);   // a key in two tables is a bug
        return all;
    }

    public static string Get(string key, params object?[] args) => Format(IsJapanese ? AllJa : AllEn, key, args);

    // For text not tied to a request, e.g. alert notifications in the configured language.
    public static string GetIn(string language, string key, params object?[] args) =>
        Format(language.StartsWith("ja", StringComparison.OrdinalIgnoreCase) ? AllJa : AllEn, key, args);

    private static string Format(IReadOnlyDictionary<string, string> dict, string key, object?[] args)
    {
        var format = dict.TryGetValue(key, out var s) ? s : AllEn.GetValueOrDefault(key, key);
        return args.Length == 0 ? format : string.Format(CultureInfo.InvariantCulture, format, args);
    }

    public static string Join(IdentityResult result) =>
        string.Join(" / ", result.Errors.Select(e => e.Description));
}

// Japanese descriptions for the Identity errors this app can produce;
// English falls through to the built-in defaults.
public class LocalizedIdentityErrorDescriber : IdentityErrorDescriber
{
    private static bool Ja => Messages.IsJapanese;

    private static IdentityError Error(IdentityError en, string ja) =>
        Ja ? new IdentityError { Code = en.Code, Description = ja } : en;

    public override IdentityError PasswordMismatch() =>
        Error(base.PasswordMismatch(), "現在のパスワードが正しくありません。");
    public override IdentityError PasswordTooShort(int length) =>
        Error(base.PasswordTooShort(length), $"パスワードは {length} 文字以上にしてください。");
    public override IdentityError PasswordRequiresUniqueChars(int uniqueChars) =>
        Error(base.PasswordRequiresUniqueChars(uniqueChars), $"パスワードには {uniqueChars} 種類以上の文字を使用してください。");
    public override IdentityError PasswordRequiresNonAlphanumeric() =>
        Error(base.PasswordRequiresNonAlphanumeric(), "パスワードには記号を 1 文字以上含めてください。");
    public override IdentityError PasswordRequiresDigit() =>
        Error(base.PasswordRequiresDigit(), "パスワードには数字を 1 文字以上含めてください。");
    public override IdentityError PasswordRequiresLower() =>
        Error(base.PasswordRequiresLower(), "パスワードには英小文字を 1 文字以上含めてください。");
    public override IdentityError PasswordRequiresUpper() =>
        Error(base.PasswordRequiresUpper(), "パスワードには英大文字を 1 文字以上含めてください。");
    public override IdentityError DuplicateUserName(string userName) =>
        Error(base.DuplicateUserName(userName), $"ユーザー名「{userName}」はすでに使用されています。");
    public override IdentityError InvalidUserName(string? userName) =>
        Error(base.InvalidUserName(userName), $"ユーザー名「{userName}」は使用できません。使用できる文字は、英数字と - . _ @ + です。");
    public override IdentityError DuplicateEmail(string email) =>
        Error(base.DuplicateEmail(email), $"メールアドレス「{email}」はすでに使用されています。");
    public override IdentityError InvalidEmail(string? email) =>
        Error(base.InvalidEmail(email), $"メールアドレス「{email}」は正しくありません。");
}
