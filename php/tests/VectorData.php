<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\ArgonGuardProfile;
use ArgonGuard\Passwords\InvalidInputException;
use ArgonGuard\Passwords\MalformedHashException;
use ArgonGuard\Passwords\PolicyViolationException;
use ArgonGuard\Passwords\UnsupportedAlgorithmException;
use ArgonGuard\Passwords\UnsupportedEnvironmentException;

/** 凍結向量與規格 artifact 載入 helper（權威來源：spec/）。 */
final class VectorData
{
    public const SPEC_DIR = __DIR__ . '/../../spec';

    private function __construct()
    {
    }

    /** @return list<array<string, mixed>> */
    public static function entries(string $file): array
    {
        $json = self::loadJson(self::SPEC_DIR . '/vectors/v1/' . $file);

        return $json['entries'];
    }

    /** @return array<string, mixed> */
    public static function entry(string $file, string $id): array
    {
        foreach (self::entries($file) as $entry) {
            if ($entry['id'] === $id) {
                return $entry;
            }
        }

        throw new \RuntimeException("{$file}: {$id} not found");
    }

    /** @return array<string, mixed> */
    public static function engineUnits(): array
    {
        return self::loadJson(self::SPEC_DIR . '/engine-units.json');
    }

    /** @return array<string, mixed> */
    public static function reasonCodes(): array
    {
        return self::loadJson(self::SPEC_DIR . '/reason-codes.json');
    }

    /** @return class-string<\ArgonGuard\Passwords\ArgonGuardException> */
    public static function errorClass(string $name): string
    {
        return match ($name) {
            'MalformedHash' => MalformedHashException::class,
            'UnsupportedAlgorithm' => UnsupportedAlgorithmException::class,
            'PolicyViolation' => PolicyViolationException::class,
            'InvalidInput' => InvalidInputException::class,
            'UnsupportedEnvironment' => UnsupportedEnvironmentException::class,
            default => throw new \RuntimeException("unknown error category: {$name}"),
        };
    }

    public static function profile(string $name): ArgonGuardProfile
    {
        return match ($name) {
            'default' => ArgonGuardProfile::Default,
            'high' => ArgonGuardProfile::High,
            'highest' => ArgonGuardProfile::Highest,
            default => throw new \RuntimeException("unknown profile: {$name}"),
        };
    }

    public static function hex(string $hex): string
    {
        return $hex === '' ? '' : (string) hex2bin($hex);
    }

    /** @return array<string, mixed> */
    private static function loadJson(string $path): array
    {
        return json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
    }
}
