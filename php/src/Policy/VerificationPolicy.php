<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Policy;

use ArgonGuard\Passwords\Phc\PhcHash;
use ArgonGuard\Passwords\ReasonCodes;

/**
 * 驗證端參數政策（SPEC §4）：OWASP frontier 凍結表（地板）＋天花板（DoS 防護）。
 * 純函式、無雜湊運算。常數與 spec/engine-units.json 一致（conformance 互相印證）。
 *
 * @internal 不屬於公開 API。
 */
final class VerificationPolicy
{
    public const MAX_M = 262144;
    public const MAX_T = 8;
    public const MIN_SALT_BYTES = 16;
    public const MAX_SALT_BYTES = 64;
    public const MIN_TAG_BYTES = 32;
    public const MAX_TAG_BYTES = 128;
    public const MAX_ENCODED_LENGTH = 512;
    public const REQUIRED_VERSION = 19;

    private function __construct()
    {
    }

    /**
     * 政策檢查。回傳 null＝通過；否則回傳 reason code（呼叫端決定 dispatch 或拋錯）。
     * 檢查順序（跨語言一致，baseline §3 釘死）：
     * missing_version → unsupported_version → keyid → data → p → t 天花板 → m 天花板 → frontier → salt → tag。
     */
    public static function check(PhcHash $hash): ?string
    {
        if ($hash->version === null) {
            return ReasonCodes::MISSING_VERSION;
        }
        if ($hash->version !== self::REQUIRED_VERSION) {
            return ReasonCodes::UNSUPPORTED_VERSION;
        }
        if ($hash->hasKeyid) {
            return ReasonCodes::KEYID_NOT_ALLOWED;
        }
        if ($hash->hasData) {
            return ReasonCodes::DATA_NOT_ALLOWED;
        }
        if ($hash->p !== 1) {
            return ReasonCodes::P_NOT_ONE;
        }
        if ($hash->t > self::MAX_T) {
            return ReasonCodes::T_ABOVE_CEILING;
        }
        if ($hash->m > self::MAX_M) {
            return ReasonCodes::M_ABOVE_CEILING;
        }
        if ($hash->t < 1 || $hash->m < self::frontierMinM($hash->t)) {
            return ReasonCodes::BELOW_OWASP_FRONTIER;
        }
        $saltLen = strlen($hash->salt);
        if ($saltLen < self::MIN_SALT_BYTES || $saltLen > self::MAX_SALT_BYTES) {
            return ReasonCodes::SALT_LENGTH_OUT_OF_RANGE;
        }
        $tagLen = strlen($hash->tag);
        if ($tagLen < self::MIN_TAG_BYTES || $tagLen > self::MAX_TAG_BYTES) {
            return ReasonCodes::TAG_LENGTH_OUT_OF_RANGE;
        }

        return null;
    }

    /** OWASP frontier 凍結表（查證 2026-07-05；spec MINOR 才可調整）。 */
    public static function frontierMinM(int $t): int
    {
        return match ($t) {
            1 => 47104,
            2 => 19456,
            3 => 12288,
            4 => 9216,
            default => 7168, // t >= 5
        };
    }
}
