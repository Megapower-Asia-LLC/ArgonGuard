namespace ArgonGuard.Passwords.Engine;

/// <summary>
/// 內部引擎邊界（SPEC §8.5）：密碼學層委外、可抽換（備援 Isopoh，見 ADR 0004）。
/// 引擎型別不得洩漏到公開 API。
/// </summary>
internal interface IArgon2Provider
{
    /// <summary>Argon2id raw tag。<paramref name="m"/> 單位 KiB（spec/engine-units.json）。</summary>
    byte[] HashRaw(byte[] password, byte[] salt, int m, int t, int p, int tagLength);
}
