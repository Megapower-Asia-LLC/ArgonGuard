namespace ArgonGuard.Passwords.Phc;

/// <summary>嚴格解析後的 PHC 欄位。<c>Algorithm</c> 保留原字串供 dispatch 判斷是否 argon2id。</summary>
internal sealed class PhcHash
{
    public PhcHash(string algorithm, long? version, long m, long t, long p,
                   byte[] salt, byte[] tag, bool hasKeyid, bool hasData)
    {
        Algorithm = algorithm;
        Version = version;
        M = m;
        T = t;
        P = p;
        Salt = salt;
        Tag = tag;
        HasKeyid = hasKeyid;
        HasData = hasData;
    }

    public string Algorithm { get; }
    public long? Version { get; }
    public long M { get; }
    public long T { get; }
    public long P { get; }
    public byte[] Salt { get; }
    public byte[] Tag { get; }
    public bool HasKeyid { get; }
    public bool HasData { get; }
}
