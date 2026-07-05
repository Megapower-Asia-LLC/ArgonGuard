<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Tests;

use ArgonGuard\Passwords\Phc\PhcHash;
use ArgonGuard\Passwords\Policy\VerificationPolicy;
use ArgonGuard\Passwords\ReasonCodes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** 政策每維度 reason code 與裁決順序（SPEC §4；baseline §3）。 */
final class VerificationPolicyTest extends TestCase
{
    private static function hash(
        ?int $version = 19,
        int $m = 19456,
        int $t = 2,
        int $p = 1,
        int $saltLen = 16,
        int $tagLen = 32,
        bool $hasKeyid = false,
        bool $hasData = false,
    ): PhcHash {
        return new PhcHash(
            'argon2id',
            $version,
            $m,
            $t,
            $p,
            str_repeat("\xAA", $saltLen),
            str_repeat("\xBB", $tagLen),
            $hasKeyid,
            $hasData,
        );
    }

    /** @return iterable<string, array{PhcHash, ?string}> */
    public static function policyCases(): iterable
    {
        // 通過
        yield 'pass-default' => [self::hash(), null];
        yield 'pass-frontier-t1' => [self::hash(m: 47104, t: 1), null];
        yield 'pass-frontier-t3' => [self::hash(m: 12288, t: 3), null];
        yield 'pass-frontier-t4' => [self::hash(m: 9216, t: 4), null];
        yield 'pass-frontier-t5' => [self::hash(m: 7168, t: 5), null];
        yield 'pass-t8-ceiling' => [self::hash(m: 7168, t: 8), null];
        yield 'pass-m-ceiling' => [self::hash(m: 262144), null];
        yield 'pass-salt-64' => [self::hash(saltLen: 64), null];
        yield 'pass-tag-128' => [self::hash(tagLen: 128), null];

        // 每維度違規
        yield 'missing-version' => [self::hash(version: null), ReasonCodes::MISSING_VERSION];
        yield 'unsupported-version-16' => [self::hash(version: 16), ReasonCodes::UNSUPPORTED_VERSION];
        yield 'keyid' => [self::hash(hasKeyid: true), ReasonCodes::KEYID_NOT_ALLOWED];
        yield 'data' => [self::hash(hasData: true), ReasonCodes::DATA_NOT_ALLOWED];
        yield 'p-zero' => [self::hash(p: 0), ReasonCodes::P_NOT_ONE];
        yield 'p-two' => [self::hash(p: 2), ReasonCodes::P_NOT_ONE];
        yield 't-nine' => [self::hash(m: 7168, t: 9), ReasonCodes::T_ABOVE_CEILING];
        yield 'm-above-ceiling' => [self::hash(m: 262145), ReasonCodes::M_ABOVE_CEILING];
        yield 'frontier-t1-46080' => [self::hash(m: 46080, t: 1), ReasonCodes::BELOW_OWASP_FRONTIER];
        yield 'frontier-t2-18432' => [self::hash(m: 18432, t: 2), ReasonCodes::BELOW_OWASP_FRONTIER];
        yield 'frontier-t3-12287' => [self::hash(m: 12287, t: 3), ReasonCodes::BELOW_OWASP_FRONTIER];
        yield 'frontier-t4-9215' => [self::hash(m: 9215, t: 4), ReasonCodes::BELOW_OWASP_FRONTIER];
        yield 'frontier-t5-7167' => [self::hash(m: 7167, t: 5), ReasonCodes::BELOW_OWASP_FRONTIER];
        yield 't-zero' => [self::hash(t: 0), ReasonCodes::BELOW_OWASP_FRONTIER];
        yield 'salt-15' => [self::hash(saltLen: 15), ReasonCodes::SALT_LENGTH_OUT_OF_RANGE];
        yield 'salt-65' => [self::hash(saltLen: 65), ReasonCodes::SALT_LENGTH_OUT_OF_RANGE];
        yield 'tag-31' => [self::hash(tagLen: 31), ReasonCodes::TAG_LENGTH_OUT_OF_RANGE];
        yield 'tag-129' => [self::hash(tagLen: 129), ReasonCodes::TAG_LENGTH_OUT_OF_RANGE];
    }

    #[DataProvider('policyCases')]
    public function testCheck(PhcHash $hash, ?string $expectedReason): void
    {
        self::assertSame($expectedReason, VerificationPolicy::check($hash));
    }

    /** 多重違規時回報第一個命中者（baseline §3 裁決順序）。 */
    public function testMultipleViolationsReportFirstHitInBaselineOrder(): void
    {
        // missing_version 先於其他一切
        self::assertSame(
            ReasonCodes::MISSING_VERSION,
            VerificationPolicy::check(self::hash(version: null, p: 2, m: 999999, t: 99)),
        );
        // keyid 先於 p
        self::assertSame(
            ReasonCodes::KEYID_NOT_ALLOWED,
            VerificationPolicy::check(self::hash(hasKeyid: true, hasData: true, p: 2)),
        );
        // p 先於 t 天花板
        self::assertSame(
            ReasonCodes::P_NOT_ONE,
            VerificationPolicy::check(self::hash(p: 2, t: 99, m: 999999)),
        );
        // t 天花板先於 m 天花板
        self::assertSame(
            ReasonCodes::T_ABOVE_CEILING,
            VerificationPolicy::check(self::hash(t: 9, m: 999999)),
        );
        // m 天花板先於 frontier
        self::assertSame(
            ReasonCodes::M_ABOVE_CEILING,
            VerificationPolicy::check(self::hash(m: 262145, t: 8, saltLen: 8)),
        );
        // frontier 先於 salt
        self::assertSame(
            ReasonCodes::BELOW_OWASP_FRONTIER,
            VerificationPolicy::check(self::hash(m: 7167, t: 5, saltLen: 8, tagLen: 16)),
        );
        // salt 先於 tag
        self::assertSame(
            ReasonCodes::SALT_LENGTH_OUT_OF_RANGE,
            VerificationPolicy::check(self::hash(saltLen: 8, tagLen: 16)),
        );
    }

    /** frontier 表與 engine-units.json 權威值一致（SPEC §10 conformance 條件 4）。 */
    public function testFrontierMatchesEngineUnits(): void
    {
        $frontier = VectorData::engineUnits()['verificationPolicy']['owaspFrontier'];
        foreach ($frontier as $row) {
            self::assertSame($row['min_m_kib'], VerificationPolicy::frontierMinM($row['t']));
        }
        // t >= 5 全部 7168
        self::assertSame(7168, VerificationPolicy::frontierMinM(6));
        self::assertSame(7168, VerificationPolicy::frontierMinM(8));

        $ceiling = VectorData::engineUnits()['verificationPolicy']['ceiling'];
        self::assertSame($ceiling['max_m_kib'], VerificationPolicy::MAX_M);
        self::assertSame($ceiling['max_t'], VerificationPolicy::MAX_T);
        self::assertSame($ceiling['maxSaltBytes'], VerificationPolicy::MAX_SALT_BYTES);
        self::assertSame($ceiling['maxTagBytes'], VerificationPolicy::MAX_TAG_BYTES);
        self::assertSame($ceiling['maxEncodedLength'], VerificationPolicy::MAX_ENCODED_LENGTH);

        $floors = VectorData::engineUnits()['verificationPolicy']['floors'];
        self::assertSame($floors['minSaltBytes'], VerificationPolicy::MIN_SALT_BYTES);
        self::assertSame($floors['minTagBytes'], VerificationPolicy::MIN_TAG_BYTES);
        self::assertSame($floors['requiredVersion'], VerificationPolicy::REQUIRED_VERSION);
    }

    /** reason code 常數 vs spec/reason-codes.json（bit-identical；SPEC §7）。 */
    public function testReasonCodeConstantsMatchAuthoritativeJson(): void
    {
        $categories = VectorData::reasonCodes()['categories'];
        $all = array_merge(...array_map(static fn (array $c): array => $c['codes'], array_values($categories)));

        $constants = (new \ReflectionClass(ReasonCodes::class))->getConstants();
        sort($all);
        $actual = array_values($constants);
        sort($actual);
        self::assertSame($all, $actual);
    }
}
