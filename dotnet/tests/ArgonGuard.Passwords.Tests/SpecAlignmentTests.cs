using System;
using System.IO;
using System.Reflection;
using System.Text.Json;
using ArgonGuard.Passwords.Internal;
using Xunit;

namespace ArgonGuard.Passwords.Tests;

/// <summary>程式碼常數與權威 artifact（engine-units.json）互相印證＋constant-time 結構斷言。</summary>
public class SpecAlignmentTests
{
    [Theory]
    [InlineData("default", ArgonGuardProfile.Default)]
    [InlineData("high", ArgonGuardProfile.High)]
    [InlineData("highest", ArgonGuardProfile.Highest)]
    public void ProfileConstants_MatchEngineUnitsJson(string name, ArgonGuardProfile profile)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorData.SpecFile("engine-units.json")));
        var expected = doc.RootElement.GetProperty("profiles").GetProperty(name);
        // 以固定 salt 產生一次並解析欄位（不依賴 internal 型別曝露參數）
        var hasher = new ArgonGuardPasswordHasher(profile);
        var encoded = hasher.HashPassword("probe-password");
        var paramSegment = encoded.Split('$')[3];
        Assert.Equal(
            $"m={expected.GetProperty("m_kib").GetInt32()},t={expected.GetProperty("t").GetInt32()},p={expected.GetProperty("p").GetInt32()}",
            paramSegment);
    }

    [Fact]
    public void SpecVersion_Is100() => Assert.Equal("1.0.0", SpecVersion.Value);

    [Fact]
    public void DefaultSentinel_19456_2_1()
    {
        var encoded = new ArgonGuardPasswordHasher().HashPassword("sentinel");
        Assert.Contains("$m=19456,t=2,p=1$", encoded, StringComparison.Ordinal);
    }

    [Fact]
    public void SamePassword_ProducesDifferentHashes_UniqueSalt()
    {
        var hasher = new ArgonGuardPasswordHasher();
        Assert.NotEqual(hasher.HashPassword("same"), hasher.HashPassword("same"));
    }

    // ---- constant-time 雙層 DoD (a)：結構性斷言（擋 merge；net8.0 與 net48 皆跑）----

    [Fact]
    public void Polyfill_HasNoInliningAndNoOptimizationFlags()
    {
        var method = typeof(FixedTimeEquals).GetMethod("Polyfill", BindingFlags.NonPublic | BindingFlags.Static)!;
        var flags = method.MethodImplementationFlags;
        Assert.True(flags.HasFlag(MethodImplAttributes.NoInlining), "Polyfill must be NoInlining");
        Assert.True(flags.HasFlag(MethodImplAttributes.NoOptimization), "Polyfill must be NoOptimization");
    }

    [Fact]
    public void Polyfill_FunctionalEquivalence_RandomPairs()
    {
        var rng = new Random(1337); // 固定 seed（CI 可重現）
        for (int round = 0; round < 2000; round++)
        {
            var len = rng.Next(0, 65);
            var a = new byte[len];
            var b = new byte[rng.Next(0, 2) == 0 ? len : rng.Next(0, 65)];
            rng.NextBytes(a);
            rng.NextBytes(b);
            if (rng.Next(0, 2) == 0 && a.Length == b.Length) Array.Copy(a, b, a.Length);
            var naive = a.Length == b.Length && ((ReadOnlySpan<byte>)a).SequenceEqual(b);
            Assert.Equal(naive, FixedTimeEquals.Polyfill(a, b));
        }
    }

    [Fact]
    public void Polyfill_PrefixVsSuffixDifference_SameResult()
    {
        var baseline = new byte[32];
        var prefixDiff = new byte[32];
        var suffixDiff = new byte[32];
        prefixDiff[0] = 1;
        suffixDiff[31] = 1;
        Assert.False(FixedTimeEquals.Polyfill(baseline, prefixDiff));
        Assert.False(FixedTimeEquals.Polyfill(baseline, suffixDiff));
    }

    [Fact]
    public void Version_2Pow32Plus19_MustNotWrapTo19()
    {
        // SPEC §4 S4：數字不得靜默 wrap——v=4294967315 (2^32+19) 必須是 unsupported_version
        var hasher = new ArgonGuardPasswordHasher();
        var salt = Convert.ToBase64String(new byte[16]).TrimEnd('=');
        var tag = Convert.ToBase64String(new byte[32]).TrimEnd('=');
        var encoded = $"$argon2id$v=4294967315$m=19456,t=2,p=1${salt}${tag}";
        var ex = Assert.Throws<PolicyViolationException>(() => hasher.VerifyPassword("x", encoded));
        Assert.Equal("policy_violation.unsupported_version", ex.Reason);
    }
}
