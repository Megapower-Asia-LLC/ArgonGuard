namespace ArgonGuard.Passwords;

/// <summary>ArgonGuard 三核心操作（SPEC §6.1）。v1 僅同步（不出假 async；需卸載自行 Task.Run）。</summary>
public interface IArgonGuardPasswordHasher
{
    /// <summary>以 active profile＋每次新產 16-byte CSPRNG salt 產生 PHC 字串。</summary>
    string HashPassword(string password);

    /// <summary>驗證密碼。回傳 false 只有一個意思：格式合法、政策合規、密碼不符（SPEC V1）。</summary>
    bool VerifyPassword(string password, string encodedHash);

    /// <summary>此雜湊是否非以現行 active profile 的精確參數產生（純解析比較，不做雜湊）。</summary>
    bool NeedsRehash(string encodedHash);
}
