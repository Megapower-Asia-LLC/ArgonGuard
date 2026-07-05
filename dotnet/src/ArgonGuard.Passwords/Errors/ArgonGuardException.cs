using System;

namespace ArgonGuard.Passwords;

/// <summary>
/// ArgonGuard typed error 基底。訊息不含密碼、salt 或 tag（SPEC §7）；
/// <see cref="Reason"/> 為跨語言 bit-identical 的 reason code（spec/reason-codes.json）。
/// </summary>
public abstract class ArgonGuardException : Exception
{
    /// <summary>建立 typed error。</summary>
    protected ArgonGuardException(string reason, string message) : base(message) => Reason = reason;

    /// <summary>機器可讀 reason code，字串以 spec/reason-codes.json 為權威。</summary>
    public string Reason { get; }
}

/// <summary>無法以嚴格文法解析為 PHC argon2id 字串（SPEC §7 MalformedHash）。</summary>
public sealed class MalformedHashException : ArgonGuardException
{
    /// <summary>以 reason code（spec/reason-codes.json）建立。</summary>
    public MalformedHashException(string reason) : base(reason, $"Encoded hash is malformed ({reason}).") { }
}

/// <summary>可解析但演算法非 argon2id，且無 legacy verifier 認領（SPEC §7）。</summary>
public sealed class UnsupportedAlgorithmException : ArgonGuardException
{
    /// <summary>以 reason code（spec/reason-codes.json）建立。</summary>
    public UnsupportedAlgorithmException(string reason) : base(reason, $"Hash algorithm is not supported ({reason}).") { }
}

/// <summary>合法 argon2id 但參數落在驗證政策之外，且無 legacy verifier 認領（SPEC §4/§7）。</summary>
public sealed class PolicyViolationException : ArgonGuardException
{
    /// <summary>以 reason code（spec/reason-codes.json）建立。</summary>
    public PolicyViolationException(string reason) : base(reason, $"Hash parameters violate the verification policy ({reason}).") { }
}

/// <summary>密碼輸入違反輸入正規化規則（SPEC §5/§7）。</summary>
public sealed class InvalidInputException : ArgonGuardException
{
    /// <summary>以 reason code（spec/reason-codes.json）建立。</summary>
    public InvalidInputException(string reason) : base(reason, $"Password input is invalid ({reason}).") { }
}

/// <summary>執行環境無法提供 argon2id（SPEC §7；.NET 引擎為純 managed，正常情況不會發生）。</summary>
public sealed class UnsupportedEnvironmentException : ArgonGuardException
{
    /// <summary>以 reason code（spec/reason-codes.json）建立。</summary>
    public UnsupportedEnvironmentException(string reason) : base(reason, $"Environment cannot provide argon2id ({reason}).") { }
}
