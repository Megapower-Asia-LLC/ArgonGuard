using System.Runtime.CompilerServices;

namespace ArgonGuard.Passwords.Internal;

/// <summary>
/// Constant-time 比較（SPEC §8.1）。
/// net8.0 委派 CryptographicOperations.FixedTimeEquals；netstandard2.0 走 <see cref="Polyfill"/>。
/// Polyfill 於兩個 TFM 皆編譯（僅 netstandard2.0 實際使用），使結構斷言與等價測試
/// 能在 net8.0 與 net48 兩個 CI job 皆執行（master plan M2-T4）。
/// </summary>
internal static class FixedTimeEquals
{
    public static bool Equals(byte[] left, byte[] right)
    {
#if NET8_0_OR_GREATER
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);
#else
        return Polyfill(left, right);
#endif
    }

    /// <summary>
    /// 結構化 XOR 累加 polyfill（normative 要求）：
    /// 長度不等仍對 left 全長走完固定迴圈（比較對象換成 left 自身）、無 early return、
    /// NoInlining|NoOptimization 防 JIT 短路優化（測試以 reflection 斷言 IL 旗標存在）。
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    internal static bool Polyfill(byte[] left, byte[] right)
    {
        int lengthDiff = left.Length ^ right.Length;
        byte[] other = lengthDiff == 0 ? right : left;
        int acc = lengthDiff;
        for (int i = 0; i < left.Length; i++)
        {
            acc |= left[i] ^ other[i];
        }
        return acc == 0;
    }
}
