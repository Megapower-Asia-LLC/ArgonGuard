using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using ArgonGuard.Passwords.Engine;
using ArgonGuard.Passwords.Internal;
using ArgonGuard.Passwords.Phc;
using ArgonGuard.Passwords.Policy;

namespace ArgonGuard.Passwords;

/// <summary>
/// ArgonGuard 密碼雜湊器（.NET 參考實作）。
/// 標準升級流程（SPEC §6.1）：
/// <code>
/// if (hasher.VerifyPassword(pw, stored)) {
///     if (hasher.NeedsRehash(stored)) store(hasher.HashPassword(pw));
///     LoginOk();
/// }
/// </code>
/// </summary>
public sealed class ArgonGuardPasswordHasher : IArgonGuardPasswordHasher
{
    // 拒絕非 well-formed 輸入的嚴格 UTF-8（SPEC §5 I4）
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly ProfileParameters _active;
    private readonly ILegacyPasswordVerifier[] _legacyVerifiers; // 建構時複製，之後不可變（SPEC L1）
    private readonly IArgon2Provider _engine;

    /// <param name="profile">強度檔位（預設 <see cref="ArgonGuardProfile.Default"/>）。</param>
    /// <param name="legacyVerifiers">Legacy verifier 有序清單；建構時複製為不可變（SPEC §6.4）。</param>
    public ArgonGuardPasswordHasher(ArgonGuardProfile profile = ArgonGuardProfile.Default,
                                    IEnumerable<ILegacyPasswordVerifier>? legacyVerifiers = null)
        : this(profile, legacyVerifiers, new KonsciousProvider())
    {
    }

    internal ArgonGuardPasswordHasher(ArgonGuardProfile profile,
                                      IEnumerable<ILegacyPasswordVerifier>? legacyVerifiers,
                                      IArgon2Provider engine)
    {
        ActiveProfile = profile;
        _active = ProfileParameters.For(profile);
        _legacyVerifiers = legacyVerifiers is null ? Array.Empty<ILegacyPasswordVerifier>() : CopyVerifiers(legacyVerifiers);
        _engine = engine;
    }

    /// <summary>現行 active 檔位。</summary>
    public ArgonGuardProfile ActiveProfile { get; }

    /// <inheritdoc />
    public string HashPassword(string password)
    {
        var passwordBytes = ValidatePassword(password);
        var salt = new byte[_active.SaltBytes];
        FillRandom(salt);
        var tag = _engine.HashRaw(passwordBytes, salt, _active.M, _active.T, _active.P, _active.TagBytes);
        return PhcParser.Encode(_active.M, _active.T, _active.P, salt, tag);
    }

    /// <inheritdoc />
    public bool VerifyPassword(string password, string encodedHash)
    {
        var passwordBytes = ValidatePassword(password);
        if (encodedHash is null) throw new MalformedHashException(ReasonCodes.NotPhc);

        // SPEC §6.2 步驟 2：解析前長度預檢
        if (encodedHash.Length > VerificationPolicy.MaxEncodedLength)
            throw new MalformedHashException(ReasonCodes.EncodedTooLong);

        // §6.2 3b 前置：演算法 token 判斷（非 argon2id 不套 argon2 嚴格文法）
        var algorithm = PhcParser.TryGetAlgorithm(encodedHash);
        if (!string.Equals(algorithm, "argon2id", StringComparison.Ordinal))
        {
            if (TryLegacy(password, encodedHash, out var legacyResult)) return legacyResult;
            throw algorithm is null
                ? new MalformedHashException(ReasonCodes.NotPhc)
                : new UnsupportedAlgorithmException(ReasonCodes.UnsupportedAlgorithm);
        }

        PhcHash parsed;
        try
        {
            parsed = PhcParser.Parse(encodedHash);
        }
        catch (MalformedHashException ex)
        {
            // §6.2 3b：argon2id 但嚴格文法解析失敗 → legacy；無人認領 → 原 MalformedHash
            if (TryLegacy(password, encodedHash, out var legacyResult)) return legacyResult;
            throw new MalformedHashException(ex.Reason);
        }

        var violation = VerificationPolicy.Check(parsed);
        if (violation is not null)
        {
            // §6.2 3a：out-of-policy argon2id → 顯式註冊的 legacy 才可認領（看得見的 opt-in）
            if (TryLegacy(password, encodedHash, out var legacyResult)) return legacyResult;
            throw new PolicyViolationException(violation);
        }

        var recomputed = _engine.HashRaw(passwordBytes, parsed.Salt, checked((int)parsed.M), checked((int)parsed.T),
                                         checked((int)parsed.P), parsed.Tag.Length);
        return FixedTimeEquals.Equals(parsed.Tag, recomputed);
    }

    /// <inheritdoc />
    public bool NeedsRehash(string encodedHash)
    {
        if (encodedHash is null) throw new MalformedHashException(ReasonCodes.NotPhc);
        if (encodedHash.Length > VerificationPolicy.MaxEncodedLength)
            throw new MalformedHashException(ReasonCodes.EncodedTooLong);

        var algorithm = PhcParser.TryGetAlgorithm(encodedHash);
        if (!string.Equals(algorithm, "argon2id", StringComparison.Ordinal))
        {
            // SPEC §6.3 N2：legacy 認領恆 true
            if (IsClaimedByLegacy(encodedHash)) return true;
            throw algorithm is null
                ? new MalformedHashException(ReasonCodes.NotPhc)
                : new UnsupportedAlgorithmException(ReasonCodes.UnsupportedAlgorithm);
        }

        PhcHash parsed;
        try
        {
            parsed = PhcParser.Parse(encodedHash);
        }
        catch (MalformedHashException)
        {
            // SPEC §6.3 N3：無人認領＝資料毀損，不得折疊成 true
            if (IsClaimedByLegacy(encodedHash)) return true;
            throw;
        }

        // 精確參數比對（含 salt/tag 長度；任一欄位不同即 true——含「更強」的情況，SPEC §6.3）
        return parsed.Version != VerificationPolicy.RequiredVersion
               || parsed.HasKeyid || parsed.HasData
               || parsed.M != _active.M
               || parsed.T != _active.T
               || parsed.P != _active.P
               || parsed.Salt.Length != _active.SaltBytes
               || parsed.Tag.Length != _active.TagBytes;
    }

    /// <summary>Conformance 測試專用（InternalsVisibleTo）：固定 salt 重現 deterministic 向量。非公開 API。</summary>
    internal string HashPasswordWithSalt(byte[] passwordBytes, byte[] salt, int m, int t, int p, int tagLength)
    {
        var tag = _engine.HashRaw(passwordBytes, salt, m, t, p, tagLength);
        return PhcParser.Encode(m, t, p, salt, tag);
    }

    private bool TryLegacy(string password, string encodedHash, out bool result)
    {
        foreach (var verifier in _legacyVerifiers)
        {
            if (verifier.CanHandle(encodedHash))
            {
                result = verifier.Verify(password, encodedHash); // 第一個認領者裁決（SPEC §6.2）
                return true;
            }
        }
        result = false;
        return false;
    }

    private bool IsClaimedByLegacy(string encodedHash)
    {
        foreach (var verifier in _legacyVerifiers)
        {
            if (verifier.CanHandle(encodedHash)) return true;
        }
        return false;
    }

    /// <summary>SPEC §5 輸入規則。檢查優先序（跨語言一致）：well-formed → empty → too_long → NUL。</summary>
    private static byte[] ValidatePassword(string password)
    {
        if (password is null) throw new InvalidInputException(ReasonCodes.PasswordEmpty);
        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(password);
        }
        catch (EncoderFallbackException)
        {
            throw new InvalidInputException(ReasonCodes.PasswordNotWellFormed);
        }
        if (bytes.Length == 0) throw new InvalidInputException(ReasonCodes.PasswordEmpty);
        if (bytes.Length > 1024) throw new InvalidInputException(ReasonCodes.PasswordTooLong);
        if (Array.IndexOf(bytes, (byte)0) >= 0) throw new InvalidInputException(ReasonCodes.PasswordContainsNul);
        return bytes;
    }

    private static ILegacyPasswordVerifier[] CopyVerifiers(IEnumerable<ILegacyPasswordVerifier> verifiers)
    {
        var list = new List<ILegacyPasswordVerifier>();
        foreach (var v in verifiers)
        {
            if (v is null) throw new ArgumentException("Legacy verifier list contains null.", nameof(verifiers));
            list.Add(v);
        }
        return list.ToArray();
    }

    private static void FillRandom(byte[] buffer)
    {
#if NET8_0_OR_GREATER
        RandomNumberGenerator.Fill(buffer);
#else
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
#endif
    }
}
