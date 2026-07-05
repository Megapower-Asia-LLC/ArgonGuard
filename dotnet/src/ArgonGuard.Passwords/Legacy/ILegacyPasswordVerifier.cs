namespace ArgonGuard.Passwords;

/// <summary>
/// Legacy 格式驗證擴充點（SPEC §6.4）。僅能於建構 <see cref="ArgonGuardPasswordHasher"/> 時
/// 以不可變有序清單注入；執行期動態註冊在 API 形狀上不可能。
/// 核心不內建任何 legacy 演算法實作；bcrypt 等完整範例見專案文件。
/// </summary>
public interface ILegacyPasswordVerifier
{
    /// <summary>廉價前綴判斷：此 verifier 是否認領該字串。不得執行昂貴運算。</summary>
    bool CanHandle(string encodedHash);

    /// <summary>驗證密碼。僅在 <see cref="CanHandle"/> 回 true 時被呼叫。</summary>
    bool Verify(string password, string encodedHash);
}
