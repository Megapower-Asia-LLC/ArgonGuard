using System;
using System.Text;

namespace ArgonGuard.Passwords.Phc;

/// <summary>
/// 嚴格 PHC parser／encoder（SPEC §2、§4 S1–S4）。
/// 文法澄清（跨語言必須一致，由單元測試與 baseline 文件釘死）：
/// 數字欄位僅允許 [0-9]、不允許前導零（值本身為 0 除外）、位數上限 15（防溢位，超限視為超天花板方向於政策層處理）；
/// base64 採 RFC 4648 §4 標準字元集、無 padding，且必須 canonical（decode 後 re-encode 必須等於原字串）。
/// </summary>
internal static class PhcParser
{
    private const string Argon2idPrefix = "argon2id";

    /// <summary>
    /// 抽出 PHC 演算法 token（dispatch 前置判斷）：字串為 "$&lt;token&gt;$…" 且 token 合法（小寫英數與 '-'）
    /// 時回傳 token，否則 null。token != "argon2id" → dispatch 走 UnsupportedAlgorithm 路徑，
    /// 不套用 argon2 嚴格文法（跨語言一致，baseline 文件釘死）。
    /// </summary>
    public static string? TryGetAlgorithm(string encoded)
    {
        if (encoded.Length < 3 || encoded[0] != '$') return null;
        int end = encoded.IndexOf('$', 1);
        if (end <= 1) return null;
        var token = encoded.Substring(1, end - 1);
        return IsLowerAlnumDash(token) ? token : null;
    }

    /// <summary>嚴格解析。失敗拋 MalformedHashException（reason 依 SPEC）。長度預檢（&gt;512）由呼叫端負責。</summary>
    public static PhcHash Parse(string encoded)
    {
        if (string.IsNullOrEmpty(encoded) || encoded[0] != '$')
            throw new MalformedHashException(ReasonCodes.NotPhc);

        var parts = encoded.Split('$');
        // ["", alg, "v=19", params, salt, tag]（有 v）或 ["", alg, params, salt, tag]（缺 v → 政策層 missing_version）
        if (parts.Length is not (5 or 6))
            throw new MalformedHashException(ReasonCodes.NotPhc);

        var algorithm = parts[1];
        if (algorithm.Length == 0 || !IsLowerAlnumDash(algorithm))
            throw new MalformedHashException(ReasonCodes.NotPhc);

        int? version = null;
        int paramsIndex = 2;
        if (parts.Length == 6)
        {
            if (!parts[2].StartsWith("v=", StringComparison.Ordinal))
                throw new MalformedHashException(ReasonCodes.NotPhc);
            version = (int)ParseNumber(parts[2].Substring(2));
            paramsIndex = 3;
        }

        var (m, t, p, hasKeyid, hasData) = ParseParams(parts[paramsIndex]);
        var salt = DecodeCanonicalBase64(parts[paramsIndex + 1]);
        var tag = DecodeCanonicalBase64(parts[paramsIndex + 2]);
        return new PhcHash(algorithm, version, m, t, p, salt, tag, hasKeyid, hasData);
    }

    /// <summary>產生端 encoder（SPEC §2 G1–G8）。</summary>
    public static string Encode(long m, long t, long p, byte[] salt, byte[] tag)
        => $"$argon2id$v=19$m={m},t={t},p={p}${EncodeBase64NoPad(salt)}${EncodeBase64NoPad(tag)}";

    private static (long M, long T, long P, bool HasKeyid, bool HasData) ParseParams(string paramSegment)
    {
        var tokens = paramSegment.Split(',');
        if (tokens.Length < 3)
            throw new MalformedHashException(IsPermutedMtp(tokens) ? ReasonCodes.ParamsOutOfOrder : ReasonCodes.NotPhc);

        // 前三個 token 必須依序為 m=、t=、p=（SPEC S1）
        if (!(tokens[0].StartsWith("m=", StringComparison.Ordinal)
              && tokens[1].StartsWith("t=", StringComparison.Ordinal)
              && tokens[2].StartsWith("p=", StringComparison.Ordinal)))
        {
            throw new MalformedHashException(IsPermutedMtp(tokens) ? ReasonCodes.ParamsOutOfOrder : ReasonCodes.NotPhc);
        }

        long m = ParseNumber(tokens[0].Substring(2));
        long t = ParseNumber(tokens[1].Substring(2));
        long p = ParseNumber(tokens[2].Substring(2));

        bool hasKeyid = false, hasData = false;
        for (int i = 3; i < tokens.Length; i++)
        {
            if (tokens[i].StartsWith("keyid=", StringComparison.Ordinal)) hasKeyid = true;
            else if (tokens[i].StartsWith("data=", StringComparison.Ordinal)) hasData = true;
            else throw new MalformedHashException(ReasonCodes.NotPhc);
        }
        return (m, t, p, hasKeyid, hasData);
    }

    /// <summary>前三 token 是否為 m/t/p 的重排（區分 params_out_of_order 與 not_phc）。</summary>
    private static bool IsPermutedMtp(string[] tokens)
    {
        if (tokens.Length < 3) return false;
        int seen = 0;
        for (int i = 0; i < 3; i++)
        {
            if (tokens[i].StartsWith("m=", StringComparison.Ordinal)) seen |= 1;
            else if (tokens[i].StartsWith("t=", StringComparison.Ordinal)) seen |= 2;
            else if (tokens[i].StartsWith("p=", StringComparison.Ordinal)) seen |= 4;
            else return false;
        }
        return seen == 7;
    }

    private static long ParseNumber(string digits)
    {
        if (digits.Length is 0 or > 15)
            throw new MalformedHashException(ReasonCodes.NotPhc);
        if (digits.Length > 1 && digits[0] == '0')
            throw new MalformedHashException(ReasonCodes.NotPhc); // 禁前導零（嚴格文法）
        long value = 0;
        foreach (var c in digits)
        {
            if (c is < '0' or > '9')
                throw new MalformedHashException(ReasonCodes.NotPhc);
            value = value * 10 + (c - '0');
        }
        return value;
    }

    private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private static byte[] DecodeCanonicalBase64(string s)
    {
        if (s.Length == 0)
            throw new MalformedHashException(ReasonCodes.BadBase64);
        foreach (var c in s)
        {
            if (Base64Alphabet.IndexOf(c) < 0)
                throw new MalformedHashException(ReasonCodes.BadBase64); // 含 '='（padding）、base64url、其他字元一律拒絕
        }
        int rem = s.Length % 4;
        if (rem == 1)
            throw new MalformedHashException(ReasonCodes.BadBase64);
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(s + new string('=', (4 - rem) % 4));
        }
        catch (FormatException)
        {
            throw new MalformedHashException(ReasonCodes.BadBase64);
        }
        // canonical 檢查：re-encode 必須還原原字串（封死 trailing-bit 可鍛性）
        if (!string.Equals(EncodeBase64NoPad(decoded), s, StringComparison.Ordinal))
            throw new MalformedHashException(ReasonCodes.BadBase64);
        return decoded;
    }

    private static string EncodeBase64NoPad(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

    private static bool IsLowerAlnumDash(string s)
    {
        foreach (var c in s)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
                return false;
        }
        return true;
    }
}
