using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace ArgonGuard.Passwords.Tests;

/// <summary>
/// README.md 的可執行副本（doc-as-test；文件與 CI 同源、防腐化）。
/// 此檔的三段程式碼與 README「Quickstart」「舊系統遷移」章節逐行對應；
/// 若公開 API 變動而文件未跟上，本測試即會轉紅。
/// </summary>
public class QuickstartExampleTest
{
    // ── README「Quickstart」：註冊 → 登入（hash → verify →（需要時）needsRehash 升級）──
    [Fact]
    public void Quickstart_RegisterThenLogin()
    {
        var password = "correct horse battery staple";

        var hasher = new ArgonGuardPasswordHasher();        // 預設 Default 檔位（m=19456 KiB, t=2, p=1）

        // 註冊時：雜湊並存進 DB
        string stored = hasher.HashPassword(password);      // 每次新產 16-byte CSPRNG salt、32-byte tag

        // 登入時：驗證＋（需要時）就地 rehash 升級
        if (hasher.VerifyPassword(password, stored))
        {
            if (hasher.NeedsRehash(stored))
                stored = hasher.HashPassword(password);     // 用新參數重雜湊後寫回 DB
            // loginOk();
        }

        // ── 斷言（README 敘述的行為）──
        Assert.StartsWith("$argon2id$v=19$m=19456,t=2,p=1$", stored);
        Assert.True(hasher.VerifyPassword(password, stored));   // 正確密碼 → true
        Assert.False(hasher.VerifyPassword("wrong", stored));   // 錯誤密碼 → false（唯一意義：密碼不符）
        Assert.False(hasher.NeedsRehash(stored));               // 剛以 active 檔位產生 → 不需 rehash
    }

    // ── README「升級無痛」：active 檔位調強後，舊雜湊於登入時逐步收斂 ──
    [Fact]
    public void RehashOnLogin_UpgradesWhenActiveProfileStrengthened()
    {
        var password = "correct horse battery staple";

        // 早期以 Default 產生並存進 DB
        string stored = new ArgonGuardPasswordHasher(ArgonGuardProfile.Default).HashPassword(password);

        // 之後 app 把 active 檔位提升到 High
        var app = new ArgonGuardPasswordHasher(ArgonGuardProfile.High);

        Assert.True(app.VerifyPassword(password, stored));  // High-active 仍能驗 Default 雜湊（Default 在 OWASP frontier 上）
        Assert.True(app.NeedsRehash(stored));               // 參數與 active（High）不同 → 需升級

        // 登入成功後就地升級
        string upgraded = app.HashPassword(password);
        Assert.StartsWith("$argon2id$v=19$m=65536,t=2,p=1$", upgraded);
        Assert.False(app.NeedsRehash(upgraded));            // 已收斂到 active 檔位
    }

    // ── README「舊系統遷移」：建構時注入 legacy verifier → 登入成功後升級到 argon2id ──
    // 註：README 的完整範例用 bcrypt（BCrypt.Net-Next）。此測試以自足的 stand-in verifier
    // 鎖住相同的 ILegacyPasswordVerifier 契約與升級機制，避免 doc-sync 測試引入外部相依。
    [Fact]
    public void LegacyMigration_VerifierClaimsThenUpgradesToArgon2id()
    {
        var password = "correct horse battery staple";

        // DB 內既有的舊格式雜湊（非 argon2id）
        string legacyStored = LegacySha256Verifier.MakeHash(password);

        // 建構時以不可變有序清單注入 legacy verifier（SPEC §6.4；runtime 無法再註冊）
        var hasher = new ArgonGuardPasswordHasher(
            ArgonGuardProfile.Default,
            new ILegacyPasswordVerifier[] { new LegacySha256Verifier() });

        string stored = legacyStored;
        if (hasher.VerifyPassword(password, stored))       // 由 legacy verifier 認領並裁決
        {
            if (hasher.NeedsRehash(stored))                // legacy 命中的字串恆為 true（SPEC §6.3 N2）
                stored = hasher.HashPassword(password);    // 就地升級到 argon2id
            // loginOk();
        }

        Assert.True(hasher.VerifyPassword(password, legacyStored)); // 舊雜湊仍可登入
        Assert.True(hasher.NeedsRehash(legacyStored));              // legacy → 恆需升級
        Assert.StartsWith("$argon2id$", stored);                    // 已升級為 argon2id
        Assert.False(hasher.NeedsRehash(stored));                   // 升級後不再需要 rehash
    }

    /// <summary>
    /// 自足的 stand-in legacy verifier（僅供 doc-sync 測試；非密碼學建議）。
    /// 結構與 README bcrypt 範例一致：cheap 前綴 CanHandle ＋ Verify。
    /// </summary>
    private sealed class LegacySha256Verifier : ILegacyPasswordVerifier
    {
        private const string Prefix = "$legacy-sha256$";

        public bool CanHandle(string encodedHash) => encodedHash.StartsWith(Prefix, StringComparison.Ordinal);

        public bool Verify(string password, string encodedHash) =>
            string.Equals(encodedHash, MakeHash(password), StringComparison.Ordinal);

        public static string MakeHash(string password)
        {
            using var sha = SHA256.Create();
            return Prefix + Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }
    }
}
