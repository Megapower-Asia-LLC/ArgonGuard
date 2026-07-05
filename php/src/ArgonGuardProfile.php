<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/** 強度檔位（閉集；SPEC §3）。公開 API 不暴露任何數字參數。 */
enum ArgonGuardProfile
{
    /** m=19456 KiB, t=2, p=1 —— OWASP 等效最低配置的 canonical 一組（永久哨兵）。 */
    case Default;

    /** m=65536 KiB (64 MiB), t=2, p=1。 */
    case High;

    /** m=131072 KiB (128 MiB), t=2, p=1。 */
    case Highest;
}
