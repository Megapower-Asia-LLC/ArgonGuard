using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Isopoh.Cryptography.Argon2;
using Xunit;

namespace ArgonGuard.BackupEngine.Tests;

/// <summary>備援引擎 Isopoh 逐筆重算凍結 deterministic 向量（raw tag byte-identical）。</summary>
public class IsopohConformanceTests
{
    private static string VectorDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "spec", "vectors", "v1");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent!;
        }
        throw new InvalidOperationException("spec/vectors/v1 not found");
    }

    public static IEnumerable<object[]> DeterministicEntries()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(VectorDir(), "deterministic.json")));
        foreach (var e in doc.RootElement.GetProperty("entries").EnumerateArray())
        {
            yield return new object[]
            {
                e.GetProperty("id").GetString()!,
                e.GetProperty("passwordHex").GetString()!,
                e.GetProperty("saltHex").GetString()!,
                e.GetProperty("m").GetInt32(),
                e.GetProperty("t").GetInt32(),
                e.GetProperty("p").GetInt32(),
                e.GetProperty("tagLen").GetInt32(),
                e.GetProperty("encoded").GetString()!,
            };
        }
    }

    [Theory]
    [MemberData(nameof(DeterministicEntries))]
    public void Isopoh_RecomputesFrozenTag(string id, string passwordHex, string saltHex,
                                           int m, int t, int p, int tagLen, string encoded)
    {
        _ = id;
        var expectedTag = DecodeNoPadBase64(encoded.Split('$')[5]);
        var config = new Argon2Config
        {
            Type = Argon2Type.HybridAddressing, // argon2id
            Version = Argon2Version.Nineteen,
            Password = Hex(passwordHex),
            Salt = Hex(saltHex),
            MemoryCost = m,
            TimeCost = t,
            Lanes = p,
            Threads = p,
            HashLength = tagLen,
            ClearPassword = false,
        };
        using var argon2 = new Argon2(config);
        using var hash = argon2.Hash();
        Assert.Equal(expectedTag, hash.Buffer);
    }

    private static byte[] Hex(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    private static byte[] DecodeNoPadBase64(string s)
        => Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
}
