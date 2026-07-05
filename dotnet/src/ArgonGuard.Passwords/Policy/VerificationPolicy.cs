using ArgonGuard.Passwords.Phc;

namespace ArgonGuard.Passwords.Policy;

/// <summary>
/// 驗證端參數政策（SPEC §4）：OWASP frontier 凍結表（地板）＋天花板（DoS 防護）。
/// 純函式、無雜湊運算。常數與 spec/engine-units.json 一致（conformance 互相印證）。
/// </summary>
internal static class VerificationPolicy
{
    // OWASP frontier（查證 2026-07-05；spec MINOR 才可調整）
    private static long FrontierMinM(long t) => t switch
    {
        1 => 47104,
        2 => 19456,
        3 => 12288,
        4 => 9216,
        _ => 7168, // t >= 5
    };

    internal const long MaxM = 262144;
    internal const long MaxT = 8;
    internal const int MinSaltBytes = 16;
    internal const int MaxSaltBytes = 64;
    internal const int MinTagBytes = 32;
    internal const int MaxTagBytes = 128;
    internal const int MaxEncodedLength = 512;
    internal const int RequiredVersion = 19;

    /// <summary>政策檢查。回傳 null＝通過；否則回傳 reason code（呼叫端決定 dispatch 或拋錯）。
    /// 檢查順序（跨語言一致，baseline 文件釘死）：版本 → keyid/data → p → 天花板(t→m) → frontier → salt → tag。</summary>
    public static string? Check(PhcHash hash)
    {
        if (hash.Version is null) return ReasonCodes.MissingVersion;
        if (hash.Version != RequiredVersion) return ReasonCodes.UnsupportedVersion;
        if (hash.HasKeyid) return ReasonCodes.KeyidNotAllowed;
        if (hash.HasData) return ReasonCodes.DataNotAllowed;
        if (hash.P != 1) return ReasonCodes.PNotOne;
        if (hash.T > MaxT) return ReasonCodes.TAboveCeiling;
        if (hash.M > MaxM) return ReasonCodes.MAboveCeiling;
        if (hash.T < 1 || hash.M < FrontierMinM(hash.T)) return ReasonCodes.BelowOwaspFrontier;
        if (hash.Salt.Length is < MinSaltBytes or > MaxSaltBytes) return ReasonCodes.SaltLengthOutOfRange;
        if (hash.Tag.Length is < MinTagBytes or > MaxTagBytes) return ReasonCodes.TagLengthOutOfRange;
        return null;
    }
}
