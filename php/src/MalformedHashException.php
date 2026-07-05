<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/** 無法以嚴格文法解析為 PHC argon2id 字串（SPEC §7 MalformedHash）。 */
final class MalformedHashException extends ArgonGuardException
{
    public function __construct(string $reason)
    {
        parent::__construct($reason, "Encoded hash is malformed ({$reason}).");
    }
}
