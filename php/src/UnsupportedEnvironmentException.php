<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/**
 * 執行環境無法提供 argon2id（SPEC §7）。
 * PHP：password_algos() 無 argon2id 且無 ext-sodium 時於建構期 fail-fast；絕不降級 bcrypt。
 */
final class UnsupportedEnvironmentException extends ArgonGuardException
{
    public function __construct(string $reason)
    {
        parent::__construct($reason, "Environment cannot provide argon2id ({$reason}).");
    }
}
