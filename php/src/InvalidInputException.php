<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/** 密碼輸入違反輸入正規化規則（SPEC §5/§7）。 */
final class InvalidInputException extends ArgonGuardException
{
    public function __construct(string $reason)
    {
        parent::__construct($reason, "Password input is invalid ({$reason}).");
    }
}
