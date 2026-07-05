using System;
using System.IO;
using System.Text.Json;

namespace ArgonGuard.Passwords.Tests;

/// <summary>凍結向量載入器：由測試輸出目錄向上尋找 repo 根的 spec/vectors/v1。</summary>
internal static class VectorData
{
    private static readonly Lazy<string> VectorDir = new(() =>
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "spec", "vectors", "v1");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("spec/vectors/v1 not found above test directory");
    });

    public static JsonElement[] Entries(string fileName)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(VectorDir.Value, fileName)));
        var entries = doc.RootElement.GetProperty("entries");
        var result = new JsonElement[entries.GetArrayLength()];
        int i = 0;
        foreach (var e in entries.EnumerateArray()) result[i++] = e.Clone();
        return result;
    }

    public static string SpecFile(string relative)
        => Path.Combine(VectorDir.Value, "..", "..", relative);

    public static byte[] Hex(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    /// <summary>bytes → .NET string（測試中重建字串型 API 輸入；向量皆為合法 UTF-8）。</summary>
    public static string Utf8(byte[] bytes) => System.Text.Encoding.UTF8.GetString(bytes);

    public static ArgonGuardProfile Profile(string name) => name switch
    {
        "default" => ArgonGuardProfile.Default,
        "high" => ArgonGuardProfile.High,
        "highest" => ArgonGuardProfile.Highest,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
    };

    public static Type ErrorType(string category) => category switch
    {
        "MalformedHash" => typeof(MalformedHashException),
        "UnsupportedAlgorithm" => typeof(UnsupportedAlgorithmException),
        "PolicyViolation" => typeof(PolicyViolationException),
        "InvalidInput" => typeof(InvalidInputException),
        "UnsupportedEnvironment" => typeof(UnsupportedEnvironmentException),
        _ => throw new ArgumentOutOfRangeException(nameof(category), category, null),
    };
}

/// <summary>needs-rehash 向量中 legacyRegistered=true 時註冊的 bcrypt 前綴認領器（不做真驗證）。</summary>
internal sealed class FakeBcryptVerifier : ILegacyPasswordVerifier
{
    public bool CanHandle(string encodedHash) => encodedHash.StartsWith("$2b$", StringComparison.Ordinal);
    public bool Verify(string password, string encodedHash) => false;
}
