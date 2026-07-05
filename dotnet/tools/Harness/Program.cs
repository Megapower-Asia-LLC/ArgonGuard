using System;
using System.Collections.Generic;
using System.Text.Json;
using ArgonGuard.Passwords;

// ArgonGuard dev harness（M2-T10；協議凍結於 spec/harness-contract.json）。
// stdin: {"schemaVersion":1,"commands":[...]} → stdout: {"schemaVersion":1,"results":[...]}
// op: hash{profile,passwordHex} / verify{passwordHex,encoded} / needsRehash{activeProfile,encoded,legacyRegistered?}

var input = JsonDocument.Parse(Console.In.ReadToEnd());
if (input.RootElement.GetProperty("schemaVersion").GetInt32() != 1)
{
    Console.Error.WriteLine("unsupported schemaVersion");
    return 2;
}

var results = new List<object>();
foreach (var cmd in input.RootElement.GetProperty("commands").EnumerateArray())
{
    try
    {
        switch (cmd.GetProperty("op").GetString())
        {
            case "hash":
            {
                var hasher = new ArgonGuardPasswordHasher(ParseProfile(cmd.GetProperty("profile").GetString()!));
                results.Add(new { ok = true, encoded = hasher.HashPassword(Utf8(cmd.GetProperty("passwordHex").GetString()!)) });
                break;
            }
            case "verify":
            {
                var hasher = new ArgonGuardPasswordHasher();
                results.Add(new
                {
                    ok = true,
                    value = hasher.VerifyPassword(Utf8(cmd.GetProperty("passwordHex").GetString()!),
                                                  cmd.GetProperty("encoded").GetString()!),
                });
                break;
            }
            case "needsRehash":
            {
                var legacy = cmd.TryGetProperty("legacyRegistered", out var lr) && lr.GetBoolean()
                    ? new ILegacyPasswordVerifier[] { new BcryptPrefixClaimer() }
                    : null;
                var hasher = new ArgonGuardPasswordHasher(ParseProfile(cmd.GetProperty("activeProfile").GetString()!), legacy);
                results.Add(new { ok = true, value = hasher.NeedsRehash(cmd.GetProperty("encoded").GetString()!) });
                break;
            }
            default:
                results.Add(new { ok = false, error = "HarnessError", reason = "unknown_op" });
                break;
        }
    }
    catch (ArgonGuardException ex)
    {
        results.Add(new { ok = false, error = ex.GetType().Name.Replace("Exception", ""), reason = ex.Reason });
    }
}

Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, results }));
return 0;

static ArgonGuardProfile ParseProfile(string name) => name switch
{
    "default" => ArgonGuardProfile.Default,
    "high" => ArgonGuardProfile.High,
    "highest" => ArgonGuardProfile.Highest,
    _ => throw new ArgumentOutOfRangeException(nameof(name)),
};

static string Utf8(string hex)
{
    var bytes = new byte[hex.Length / 2];
    for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    return System.Text.Encoding.UTF8.GetString(bytes);
}

/// <summary>harness 協議中 legacyRegistered=true 的標準認領器（與向量語意一致）。</summary>
file sealed class BcryptPrefixClaimer : ILegacyPasswordVerifier
{
    public bool CanHandle(string encodedHash) => encodedHash.StartsWith("$2b$", StringComparison.Ordinal);
    public bool Verify(string password, string encodedHash) => false;
}
