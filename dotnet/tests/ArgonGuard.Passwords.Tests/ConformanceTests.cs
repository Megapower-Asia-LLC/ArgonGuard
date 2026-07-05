using System;
using System.Collections.Generic;
using System.Text.Json;
using Xunit;

namespace ArgonGuard.Passwords.Tests;

/// <summary>凍結向量 conformance（SPEC §10）。任一紅燈＝不合規。</summary>
public class ConformanceTests
{
    private static IEnumerable<object[]> Ids(string file)
    {
        foreach (var e in VectorData.Entries(file))
            yield return new object[] { e.GetProperty("id").GetString()! };
    }

    private static JsonElement Entry(string file, string id)
    {
        foreach (var e in VectorData.Entries(file))
            if (e.GetProperty("id").GetString() == id) return e;
        throw new InvalidOperationException($"{file}: {id} not found");
    }

    public static IEnumerable<object[]> DeterministicIds() => Ids("deterministic.json");
    public static IEnumerable<object[]> VerifyIds() => Ids("verify.json");
    public static IEnumerable<object[]> RejectIds() => Ids("reject.json");
    public static IEnumerable<object[]> NeedsRehashIds() => Ids("needs-rehash.json");
    public static IEnumerable<object[]> InputLimitIds() => Ids("input-limits.json");

    [Theory]
    [MemberData(nameof(DeterministicIds))]
    public void Deterministic_EncodeMatchesFrozenVector(string id)
    {
        var e = Entry("deterministic.json", id);
        var hasher = new ArgonGuardPasswordHasher();
        var encoded = hasher.HashPasswordWithSalt(
            VectorData.Hex(e.GetProperty("passwordHex").GetString()!),
            VectorData.Hex(e.GetProperty("saltHex").GetString()!),
            e.GetProperty("m").GetInt32(), e.GetProperty("t").GetInt32(), e.GetProperty("p").GetInt32(),
            e.GetProperty("tagLen").GetInt32());
        Assert.Equal(e.GetProperty("encoded").GetString(), encoded);
    }

    [Theory]
    [MemberData(nameof(DeterministicIds))]
    public void Deterministic_VerifiesTrue(string id)
    {
        var e = Entry("deterministic.json", id);
        var hasher = new ArgonGuardPasswordHasher();
        Assert.True(hasher.VerifyPassword(
            VectorData.Utf8(VectorData.Hex(e.GetProperty("passwordHex").GetString()!)),
            e.GetProperty("encoded").GetString()!));
    }

    [Theory]
    [MemberData(nameof(VerifyIds))]
    public void Verify_MatchesExpected(string id)
    {
        var e = Entry("verify.json", id);
        var hasher = new ArgonGuardPasswordHasher();
        var actual = hasher.VerifyPassword(
            VectorData.Utf8(VectorData.Hex(e.GetProperty("passwordHex").GetString()!)),
            e.GetProperty("encoded").GetString()!);
        Assert.Equal(e.GetProperty("expected").GetBoolean(), actual);
    }

    [Theory]
    [MemberData(nameof(RejectIds))]
    public void Reject_ThrowsExactErrorAndReason(string id)
    {
        var e = Entry("reject.json", id);
        var hasher = new ArgonGuardPasswordHasher();
        var ex = Assert.Throws(
            VectorData.ErrorType(e.GetProperty("expectedError").GetString()!),
            () => hasher.VerifyPassword(
                VectorData.Utf8(VectorData.Hex(e.GetProperty("passwordHex").GetString()!)),
                e.GetProperty("encoded").GetString()!));
        Assert.Equal(e.GetProperty("expectedReason").GetString(), ((ArgonGuardException)ex).Reason);
    }

    [Theory]
    [MemberData(nameof(NeedsRehashIds))]
    public void NeedsRehash_MatchesTruthTable(string id)
    {
        var e = Entry("needs-rehash.json", id);
        var legacy = e.GetProperty("legacyRegistered").GetBoolean()
            ? new ILegacyPasswordVerifier[] { new FakeBcryptVerifier() }
            : null;
        var hasher = new ArgonGuardPasswordHasher(
            VectorData.Profile(e.GetProperty("activeProfile").GetString()!), legacy);
        var encoded = e.GetProperty("encoded").GetString()!;

        var expected = e.GetProperty("expected");
        if (expected.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            Assert.Equal(expected.GetBoolean(), hasher.NeedsRehash(encoded));
        }
        else
        {
            var ex = Assert.Throws(
                VectorData.ErrorType(expected.GetProperty("error").GetString()!),
                () => hasher.NeedsRehash(encoded));
            Assert.Equal(expected.GetProperty("reason").GetString(), ((ArgonGuardException)ex).Reason);
        }
    }

    [Theory]
    [MemberData(nameof(InputLimitIds))]
    public void InputLimits_MatchExpected(string id)
    {
        var e = Entry("input-limits.json", id);
        var hasher = new ArgonGuardPasswordHasher();

        if (e.TryGetProperty("refA", out var refA))
        {
            // NFC vs NFD：兩筆 deterministic 向量的 encoded 必須不同
            var a = Entry("deterministic.json", refA.GetString()!).GetProperty("encoded").GetString();
            var b = Entry("deterministic.json", e.GetProperty("refB").GetString()!).GetProperty("encoded").GetString();
            Assert.NotEqual(a, b);
            return;
        }

        string password;
        if (e.TryGetProperty("stringInput", out var si))
        {
            // "\\uD800ab" 標記法 → 還原為含 lone surrogate 的 .NET 字串
            var raw = si.GetString()!;
            Assert.StartsWith("\\uD800", raw, StringComparison.Ordinal);
            password = "\uD800" + raw.Substring(6);
        }
        else
        {
            password = VectorData.Utf8(VectorData.Hex(e.GetProperty("passwordHex").GetString()!));
        }

        var expected = e.GetProperty("expected");
        if (expected.ValueKind == JsonValueKind.String && expected.GetString() == "ok")
        {
            var encoded = hasher.HashPassword(password);
            Assert.True(hasher.VerifyPassword(password, encoded));
        }
        else
        {
            var ex = Assert.Throws(
                VectorData.ErrorType(expected.GetProperty("error").GetString()!),
                () => hasher.HashPassword(password));
            Assert.Equal(expected.GetProperty("reason").GetString(), ((ArgonGuardException)ex).Reason);
        }
    }
}
