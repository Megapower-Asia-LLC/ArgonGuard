<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/**
 * 檔位參數常數（與 spec/engine-units.json 一致；conformance 測試互相印證）。
 *
 * @internal 不屬於公開 API。
 */
final readonly class ProfileParameters
{
    public function __construct(
        public int $m,
        public int $t,
        public int $p,
        public int $saltBytes,
        public int $tagBytes,
    ) {
    }

    public static function forProfile(ArgonGuardProfile $profile): self
    {
        return match ($profile) {
            ArgonGuardProfile::Default => new self(19456, 2, 1, 16, 32),
            ArgonGuardProfile::High => new self(65536, 2, 1, 16, 32),
            ArgonGuardProfile::Highest => new self(131072, 2, 1, 16, 32),
        };
    }
}
