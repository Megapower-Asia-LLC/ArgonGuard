<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Phc;

use ArgonGuard\Passwords\MalformedHashException;
use ArgonGuard\Passwords\ReasonCodes;

/**
 * 嚴格 PHC parser／encoder（SPEC §2、§4 S1–S4；baseline §4 嚴格文法澄清）。
 *
 * 文法澄清（跨語言必須 bit-identical，由 .NET baseline 釘死）：
 * 數字欄位僅允許 [0-9]、不允許正負號、不允許前導零（值本身為 0 除外）、位數上限 15（防溢位）；
 * base64 採 RFC 4648 §4 標準字元集、無 padding，且必須 canonical
 * （decode 後 re-encode 必須等於原字串，封死 trailing-bit 可鍛性）；長度 mod 4 == 1 → 非法。
 *
 * @internal 不屬於公開 API。
 */
final class PhcParser
{
    private const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    private const DIGITS = '0123456789';

    private function __construct()
    {
    }

    /**
     * 抽出 PHC 演算法 token（dispatch 前置判斷；baseline §1）：字串為 "$<token>$…" 且 token 合法
     * （小寫英數與 '-'）時回傳 token，否則 null。token != "argon2id" → dispatch 走
     * UnsupportedAlgorithm 路徑，不套用 argon2 嚴格文法。
     */
    public static function tryGetAlgorithm(string $encoded): ?string
    {
        if (strlen($encoded) < 3 || $encoded[0] !== '$') {
            return null;
        }
        $end = strpos($encoded, '$', 1);
        if ($end === false || $end <= 1) {
            return null;
        }
        $token = substr($encoded, 1, $end - 1);

        return self::isLowerAlnumDash($token) ? $token : null;
    }

    /** 嚴格解析。失敗拋 MalformedHashException（reason 依 SPEC）。長度預檢（>512）由呼叫端負責。 */
    public static function parse(string $encoded): PhcHash
    {
        if ($encoded === '' || $encoded[0] !== '$') {
            throw new MalformedHashException(ReasonCodes::NOT_PHC);
        }

        $parts = explode('$', $encoded);
        // ["", alg, "v=19", params, salt, tag]（有 v）或 ["", alg, params, salt, tag]（缺 v → 政策層 missing_version）
        $count = count($parts);
        if ($count !== 5 && $count !== 6) {
            throw new MalformedHashException(ReasonCodes::NOT_PHC);
        }

        $algorithm = $parts[1];
        if ($algorithm === '' || !self::isLowerAlnumDash($algorithm)) {
            throw new MalformedHashException(ReasonCodes::NOT_PHC);
        }

        $version = null;
        $paramsIndex = 2;
        if ($count === 6) {
            // v 段有出現時必須是第 3 段且格式 v=<number>（baseline §4）
            if (!str_starts_with($parts[2], 'v=')) {
                throw new MalformedHashException(ReasonCodes::NOT_PHC);
            }
            $version = self::parseNumber(substr($parts[2], 2));
            $paramsIndex = 3;
        }

        [$m, $t, $p, $hasKeyid, $hasData] = self::parseParams($parts[$paramsIndex]);
        $salt = self::decodeCanonicalBase64($parts[$paramsIndex + 1]);
        $tag = self::decodeCanonicalBase64($parts[$paramsIndex + 2]);

        return new PhcHash($algorithm, $version, $m, $t, $p, $salt, $tag, $hasKeyid, $hasData);
    }

    /** 產生端 encoder（SPEC §2 G1–G8）。salt/tag 為 raw bytes。 */
    public static function encode(int $m, int $t, int $p, string $salt, string $tag): string
    {
        return sprintf(
            '$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s',
            $m,
            $t,
            $p,
            self::encodeBase64NoPad($salt),
            self::encodeBase64NoPad($tag),
        );
    }

    /** @return array{0:int,1:int,2:int,3:bool,4:bool} [m, t, p, hasKeyid, hasData] */
    private static function parseParams(string $paramSegment): array
    {
        $tokens = explode(',', $paramSegment);
        if (count($tokens) < 3) {
            throw new MalformedHashException(
                self::isPermutedMtp($tokens) ? ReasonCodes::PARAMS_OUT_OF_ORDER : ReasonCodes::NOT_PHC,
            );
        }

        // 前三個 token 必須依序為 m=、t=、p=（SPEC S1）
        if (!(str_starts_with($tokens[0], 'm=')
            && str_starts_with($tokens[1], 't=')
            && str_starts_with($tokens[2], 'p='))) {
            throw new MalformedHashException(
                self::isPermutedMtp($tokens) ? ReasonCodes::PARAMS_OUT_OF_ORDER : ReasonCodes::NOT_PHC,
            );
        }

        $m = self::parseNumber(substr($tokens[0], 2));
        $t = self::parseNumber(substr($tokens[1], 2));
        $p = self::parseNumber(substr($tokens[2], 2));

        $hasKeyid = false;
        $hasData = false;
        $tokenCount = count($tokens);
        for ($i = 3; $i < $tokenCount; $i++) {
            // 第 4 個起僅允許 keyid=／data= 前綴 token（→ 政策層拒絕），其他 → not_phc（baseline §4）
            if (str_starts_with($tokens[$i], 'keyid=')) {
                $hasKeyid = true;
            } elseif (str_starts_with($tokens[$i], 'data=')) {
                $hasData = true;
            } else {
                throw new MalformedHashException(ReasonCodes::NOT_PHC);
            }
        }

        return [$m, $t, $p, $hasKeyid, $hasData];
    }

    /**
     * 前三 token 是否為 m/t/p 的重排（區分 params_out_of_order 與 not_phc）。
     *
     * @param list<string> $tokens
     */
    private static function isPermutedMtp(array $tokens): bool
    {
        if (count($tokens) < 3) {
            return false;
        }
        $seen = 0;
        for ($i = 0; $i < 3; $i++) {
            if (str_starts_with($tokens[$i], 'm=')) {
                $seen |= 1;
            } elseif (str_starts_with($tokens[$i], 't=')) {
                $seen |= 2;
            } elseif (str_starts_with($tokens[$i], 'p=')) {
                $seen |= 4;
            } else {
                return false;
            }
        }

        return $seen === 7;
    }

    /** 嚴格數字：僅 [0-9]、無正負號、無前導零（單獨 "0" 除外）、位數 ≤15（PHP int 64 位，15 位十進位不溢位）。 */
    private static function parseNumber(string $digits): int
    {
        $len = strlen($digits);
        if ($len === 0 || $len > 15) {
            throw new MalformedHashException(ReasonCodes::NOT_PHC);
        }
        if ($len > 1 && $digits[0] === '0') {
            throw new MalformedHashException(ReasonCodes::NOT_PHC); // 禁前導零（嚴格文法）
        }
        if (strspn($digits, self::DIGITS) !== $len) {
            throw new MalformedHashException(ReasonCodes::NOT_PHC);
        }

        return (int) $digits;
    }

    /** 回傳 raw bytes。含 '='（padding）、base64url、其他字元、非 canonical 一律 bad_base64。 */
    private static function decodeCanonicalBase64(string $s): string
    {
        $len = strlen($s);
        if ($len === 0 || strspn($s, self::BASE64_ALPHABET) !== $len) {
            throw new MalformedHashException(ReasonCodes::BAD_BASE64);
        }
        $rem = $len % 4;
        if ($rem === 1) {
            throw new MalformedHashException(ReasonCodes::BAD_BASE64);
        }
        $decoded = base64_decode($s . str_repeat('=', (4 - $rem) % 4), true);
        if ($decoded === false) {
            throw new MalformedHashException(ReasonCodes::BAD_BASE64);
        }
        // canonical 檢查：re-encode 必須還原原字串（封死 trailing-bit 可鍛性）
        if (self::encodeBase64NoPad($decoded) !== $s) {
            throw new MalformedHashException(ReasonCodes::BAD_BASE64);
        }

        return $decoded;
    }

    private static function encodeBase64NoPad(string $data): string
    {
        return rtrim(base64_encode($data), '=');
    }

    private static function isLowerAlnumDash(string $s): bool
    {
        return strspn($s, 'abcdefghijklmnopqrstuvwxyz0123456789-') === strlen($s);
    }
}
