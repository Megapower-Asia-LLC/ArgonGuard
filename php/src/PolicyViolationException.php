<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/** 合法 argon2id 但參數落在驗證政策之外，且無 legacy verifier 認領（SPEC §4/§7）。 */
final class PolicyViolationException extends ArgonGuardException
{
    public function __construct(string $reason)
    {
        parent::__construct($reason, "Hash parameters violate the verification policy ({$reason}).");
    }
}
