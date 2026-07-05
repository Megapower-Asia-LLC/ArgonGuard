namespace ArgonGuard.Passwords;

/// <summary>強度檔位（閉集；SPEC §3）。公開 API 不暴露任何數字參數。</summary>
public enum ArgonGuardProfile
{
    /// <summary>m=19456 KiB, t=2, p=1 —— OWASP 等效最低配置的 canonical 一組（永久哨兵）。</summary>
    Default = 0,

    /// <summary>m=65536 KiB (64 MiB), t=2, p=1。</summary>
    High = 1,

    /// <summary>m=131072 KiB (128 MiB), t=2, p=1。</summary>
    Highest = 2,
}

/// <summary>檔位參數常數（與 spec/engine-units.json 一致；conformance 測試互相印證）。</summary>
internal readonly struct ProfileParameters
{
    public ProfileParameters(int m, int t, int p, int saltBytes, int tagBytes)
    {
        M = m; T = t; P = p; SaltBytes = saltBytes; TagBytes = tagBytes;
    }

    public int M { get; }
    public int T { get; }
    public int P { get; }
    public int SaltBytes { get; }
    public int TagBytes { get; }

    public static ProfileParameters For(ArgonGuardProfile profile) => profile switch
    {
        ArgonGuardProfile.Default => new ProfileParameters(19456, 2, 1, 16, 32),
        ArgonGuardProfile.High => new ProfileParameters(65536, 2, 1, 16, 32),
        ArgonGuardProfile.Highest => new ProfileParameters(131072, 2, 1, 16, 32),
        _ => throw new System.ArgumentOutOfRangeException(nameof(profile)),
    };
}
