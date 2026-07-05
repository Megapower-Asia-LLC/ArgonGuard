<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords\Phc;

/**
 * 嚴格解析後的 PHC argon2id 雜湊（salt/tag 為 raw bytes；PHP string 即 byte string）。
 *
 * @internal 不屬於公開 API。
 */
final readonly class PhcHash
{
    public function __construct(
        public string $algorithm,
        public ?int $version,
        public int $m,
        public int $t,
        public int $p,
        public string $salt,
        public string $tag,
        public bool $hasKeyid,
        public bool $hasData,
    ) {
    }
}
