<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/** 可解析但演算法非 argon2id，且無 legacy verifier 認領（SPEC §7）。 */
final class UnsupportedAlgorithmException extends ArgonGuardException
{
    public function __construct(string $reason)
    {
        parent::__construct($reason, "Hash algorithm is not supported ({$reason}).");
    }
}
