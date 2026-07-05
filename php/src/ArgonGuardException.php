<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/**
 * ArgonGuard typed error 基底。訊息不含密碼、salt 或 tag（SPEC §7）；
 * getReason() 為跨語言 bit-identical 的 reason code（spec/reason-codes.json）。
 */
abstract class ArgonGuardException extends \RuntimeException
{
    protected function __construct(private readonly string $reason, string $message)
    {
        parent::__construct($message);
    }

    /** 機器可讀 reason code，字串以 spec/reason-codes.json 為權威。 */
    public function getReason(): string
    {
        return $this->reason;
    }
}
