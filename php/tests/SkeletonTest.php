<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\SpecVersion;
use PHPUnit\Framework\TestCase;

final class SkeletonTest extends TestCase
{
    public function testSpecVersionIsDefined(): void
    {
        self::assertNotSame('', SpecVersion::VALUE);
    }
}
