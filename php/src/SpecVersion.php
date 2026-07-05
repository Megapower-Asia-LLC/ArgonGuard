<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/** ArgonGuard 規格版本資訊。 */
final class SpecVersion
{
    /** 實作的 ArgonGuard 規格版本（SPEC §9）。 */
    public const VALUE = '1.0.0';

    private function __construct()
    {
    }
}
