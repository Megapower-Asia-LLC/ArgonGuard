using Konscious.Security.Cryptography;

namespace ArgonGuard.Passwords.Engine;

/// <summary>Konscious.Security.Cryptography.Argon2 引擎（純 managed；ADR 0004）。MemorySize 單位 KiB。</summary>
internal sealed class KonsciousProvider : IArgon2Provider
{
    public byte[] HashRaw(byte[] password, byte[] salt, int m, int t, int p, int tagLength)
    {
        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            MemorySize = m,
            Iterations = t,
            DegreeOfParallelism = p,
        };
        return argon2.GetBytes(tagLength);
    }
}
