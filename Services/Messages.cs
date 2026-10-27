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
        ["auth.lockedOut"] = "This account is temporarily locked after repeated failed sign-ins. Please wait and try again.",
        ["password.changed"] = "Password changed.",
        ["password.required"] = "Please enter a password.",
        ["password.bothRequired"] = "Current and new passwords are required.",
        ["password.reset"] = "Password reset.",
        ["retention.invalidDays"] = "Retention days must be 0 or greater (0 = keep forever).",
        ["retention.forever"] = "keep forever",
        ["retention.days"] = "keep for {0} days",
        ["retention.updated"] = "Retention policy updated: {0}",
        ["retention.notSet"] = "No retention policy is set (records are kept forever). Set the retention days first.",
        ["retention.deleted"] = "Deleted {0:N0} records.",
        ["path.required"] = "Please enter a path.",
        ["path.paramRequired"] = "The path parameter is required.",
        ["path.notFound"] = "Folder not found: {0}",
        ["path.duplicate"] = "This folder is already monitored.",
        ["path.notMonitored"] = "The specified path is not monitored.",
        ["path.added"] = "Added. SACL applied to {0} items.",
        ["path.removedSacl"] = "Removed from monitoring and removed SACL from {0} items.",
        ["path.removed"] = "Removed from monitoring. (SACL entries were left in place.)",
        ["path.saclApplied"] = "SACL applied to {0} items.",
        ["path.eventTypeRequired"] = "Select at least one access type.",
        ["user.bothRequired"] = "User name and password are required.",
        ["user.created"] = "User \"{0}\" created.",
        ["user.cannotDeleteSelf"] = "You cannot delete your own account.",
        ["user.notFound"] = "User not found.",
        ["user.deleted"] = "User \"{0}\" deleted.",
        ["user.cannotChangeOwnRole"] = "You cannot change your own role.",
        ["user.invalidRole"] = "Role must be Admin or Viewer.",
        ["user.roleChanged"] = "Role changed.",
        ["alerts.saved"] = "Notification settings saved.",
        ["alerts.invalid"] = "Thresholds must be 0 or greater, and the window and cooldown must be at least 1 minute.",
        ["alerts.noChannel"] = "Set a webhook URL or email settings first.",
        ["alerts.smtpHostRequired"] = "Enter the SMTP server to send email.",
        ["alerts.mailToRequired"] = "Enter at least one email recipient.",
        ["alerts.testSent"] = "Test notification sent.",
        ["alerts.testFailed"] = "Test notification failed: {0}",
        ["alert.deleteTitle"] = "Mass deletion detected",
        ["alert.writeTitle"] = "Mass file changes detected (possible ransomware)",
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
        ["csv.fileName"] = "File Name",
        ["csv.folder"] = "Folder",
        ["csv.path"] = "Full Path",
        ["csv.ip"] = "Client IP",
        ["csv.machine"] = "Client Machine",
    };

    public static readonly IReadOnlyDictionary<string, string> Ja = new Dictionary<string, string>
    {
        ["auth.invalid"] = "ユーザー名またはパスワードが正しくありません。",
        ["auth.lockedOut"] = "ログイン失敗が続いたため一時的にロックされています。しばらく待ってから再度お試しください。",
        ["password.changed"] = "パスワードを変更しました。",
        ["password.required"] = "パスワードを入力してください。",
        ["password.bothRequired"] = "現在のパスワードと新しいパスワードは必須です。",
        ["password.reset"] = "パスワードをリセットしました。",
        ["retention.invalidDays"] = "保持日数は 0 以上を指定してください。（0 = 無期限保持）",
        ["retention.forever"] = "無期限保持",
        ["retention.days"] = "{0} 日間保持",
        ["retention.updated"] = "データ保持ポリシーを更新しました: {0}",
        ["retention.notSet"] = "データ保持ポリシーが未設定です（無期限保持）。先に保持日数を設定してください。",
        ["retention.deleted"] = "{0:N0} 件のレコードを削除しました。",
        ["path.required"] = "パスを入力してください。",
        ["path.paramRequired"] = "path パラメーターが必要です。",
        ["path.notFound"] = "フォルダが見つかりません: {0}",
        ["path.duplicate"] = "すでに監視対象に追加されています。",
        ["path.notMonitored"] = "指定されたパスは監視対象に登録されていません。",
        ["path.added"] = "追加しました。SACL を {0} 件に適用しました。",
        ["path.removedSacl"] = "監視対象から削除し、SACL を {0} 件から除去しました。",
        ["path.removed"] = "監視対象から削除しました。（SACL は残っています）",
        ["path.saclApplied"] = "SACL を {0} 件に適用しました。",
        ["path.eventTypeRequired"] = "少なくとも1種別を選択してください。",
        ["user.bothRequired"] = "ユーザー名とパスワードは必須です。",
        ["user.created"] = "ユーザー「{0}」を作成しました。",
        ["user.cannotDeleteSelf"] = "自分自身は削除できません。",
        ["user.notFound"] = "ユーザーが見つかりません。",
        ["user.deleted"] = "ユーザー「{0}」を削除しました。",
        ["user.cannotChangeOwnRole"] = "自分自身のロールは変更できません。",
        ["user.invalidRole"] = "ロールは Admin または Viewer を指定してください。",
        ["user.roleChanged"] = "ロールを変更しました。",
        ["alerts.saved"] = "通知設定を保存しました。",
        ["alerts.invalid"] = "しきい値は 0 以上、集計時間と再通知までの間隔は 1 分以上を指定してください。",
        ["alerts.noChannel"] = "先に Webhook URL またはメールの設定を行ってください。",
        ["alerts.smtpHostRequired"] = "メールを送るには SMTP サーバーを入力してください。",
        ["alerts.mailToRequired"] = "メールの宛先を 1 つ以上入力してください。",
        ["alerts.testSent"] = "テスト通知を送信しました。",
        ["alerts.testFailed"] = "テスト通知の送信に失敗しました: {0}",
        ["alert.deleteTitle"] = "大量削除を検知しました",
        ["alert.writeTitle"] = "大量のファイル変更を検知しました（ランサムウェアの可能性）",
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
        ["csv.timeUtc"] = "日時 (UTC)",
        ["csv.user"] = "ユーザー",
        ["csv.type"] = "種別",
        ["csv.fileName"] = "ファイル名",
        ["csv.folder"] = "フォルダ",
        ["csv.path"] = "フルパス",
        ["csv.ip"] = "接続元 IP",
        ["csv.machine"] = "接続元端末",
    };

    public static bool IsJapanese => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ja";

    public static string Get(string key, params object?[] args) => Format(IsJapanese ? Ja : En, key, args);

    // For text not tied to a request, e.g. alert notifications in the configured language.
    public static string GetIn(string language, string key, params object?[] args) =>
        Format(language.StartsWith("ja", StringComparison.OrdinalIgnoreCase) ? Ja : En, key, args);

    private static string Format(IReadOnlyDictionary<string, string> dict, string key, object?[] args)
    {
        var format = dict.TryGetValue(key, out var s) ? s : En.GetValueOrDefault(key, key);
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
        Error(base.PasswordRequiresUniqueChars(uniqueChars), $"パスワードには {uniqueChars} 種類以上の文字を使ってください。");
    public override IdentityError PasswordRequiresNonAlphanumeric() =>
        Error(base.PasswordRequiresNonAlphanumeric(), "パスワードには記号を 1 文字以上含めてください。");
    public override IdentityError PasswordRequiresDigit() =>
        Error(base.PasswordRequiresDigit(), "パスワードには数字を 1 文字以上含めてください。");
    public override IdentityError PasswordRequiresLower() =>
        Error(base.PasswordRequiresLower(), "パスワードには英小文字を 1 文字以上含めてください。");
    public override IdentityError PasswordRequiresUpper() =>
        Error(base.PasswordRequiresUpper(), "パスワードには英大文字を 1 文字以上含めてください。");
    public override IdentityError DuplicateUserName(string userName) =>
        Error(base.DuplicateUserName(userName), $"ユーザー名「{userName}」はすでに使われています。");
    public override IdentityError InvalidUserName(string? userName) =>
        Error(base.InvalidUserName(userName), $"ユーザー名「{userName}」は使用できません。英数字と - . _ @ + のみ使用できます。");
    public override IdentityError DuplicateEmail(string email) =>
        Error(base.DuplicateEmail(email), $"メールアドレス「{email}」はすでに使われています。");
    public override IdentityError InvalidEmail(string? email) =>
        Error(base.InvalidEmail(email), $"メールアドレス「{email}」は正しくありません。");
}
