<?php

declare(strict_types=1);

namespace ArgonGuard\Passwords;

/**
 * 機器可讀 reason code 常數。字串以 spec/reason-codes.json 為權威，
 * 四語言實作必須 bit-identical（SPEC §7）。
 */
final class ReasonCodes
{
    // MalformedHash
    public const NOT_PHC = 'malformed.not_phc';
    public const BAD_BASE64 = 'malformed.bad_base64';
    public const PARAMS_OUT_OF_ORDER = 'malformed.params_out_of_order';
    public const ENCODED_TOO_LONG = 'malformed.encoded_too_long';

    // UnsupportedAlgorithm
    public const UNSUPPORTED_ALGORITHM = 'unsupported.algorithm';

    // PolicyViolation
    public const BELOW_OWASP_FRONTIER = 'policy_violation.below_owasp_frontier';
    public const M_ABOVE_CEILING = 'policy_violation.m_above_ceiling';
    public const T_ABOVE_CEILING = 'policy_violation.t_above_ceiling';
    public const SALT_LENGTH_OUT_OF_RANGE = 'policy_violation.salt_length_out_of_range';
    public const TAG_LENGTH_OUT_OF_RANGE = 'policy_violation.tag_length_out_of_range';
    public const P_NOT_ONE = 'policy_violation.p_not_one';
    public const MISSING_VERSION = 'policy_violation.missing_version';
    public const UNSUPPORTED_VERSION = 'policy_violation.unsupported_version';
    public const KEYID_NOT_ALLOWED = 'policy_violation.keyid_not_allowed';
    public const DATA_NOT_ALLOWED = 'policy_violation.data_not_allowed';

    // InvalidInput
    public const PASSWORD_EMPTY = 'invalid_input.password_empty';
    public const PASSWORD_TOO_LONG = 'invalid_input.password_too_long';
    public const PASSWORD_CONTAINS_NUL = 'invalid_input.password_contains_nul';
    public const PASSWORD_NOT_WELL_FORMED = 'invalid_input.password_not_well_formed';

    // UnsupportedEnvironment
    public const ARGON2ID_UNAVAILABLE = 'environment.argon2id_unavailable';

    private function __construct()
    {
    }
}
