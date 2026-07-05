namespace ArgonGuard.Passwords;

/// <summary>
/// Reason code 常數。字串必須與 spec/reason-codes.json bit-identical
/// （conformance 測試以 reject 向量逐筆斷言）。
/// </summary>
internal static class ReasonCodes
{
    // MalformedHash
    public const string NotPhc = "malformed.not_phc";
    public const string BadBase64 = "malformed.bad_base64";
    public const string ParamsOutOfOrder = "malformed.params_out_of_order";
    public const string EncodedTooLong = "malformed.encoded_too_long";

    // UnsupportedAlgorithm
    public const string UnsupportedAlgorithm = "unsupported.algorithm";

    // PolicyViolation
    public const string BelowOwaspFrontier = "policy_violation.below_owasp_frontier";
    public const string MAboveCeiling = "policy_violation.m_above_ceiling";
    public const string TAboveCeiling = "policy_violation.t_above_ceiling";
    public const string SaltLengthOutOfRange = "policy_violation.salt_length_out_of_range";
    public const string TagLengthOutOfRange = "policy_violation.tag_length_out_of_range";
    public const string PNotOne = "policy_violation.p_not_one";
    public const string MissingVersion = "policy_violation.missing_version";
    public const string UnsupportedVersion = "policy_violation.unsupported_version";
    public const string KeyidNotAllowed = "policy_violation.keyid_not_allowed";
    public const string DataNotAllowed = "policy_violation.data_not_allowed";

    // InvalidInput
    public const string PasswordEmpty = "invalid_input.password_empty";
    public const string PasswordTooLong = "invalid_input.password_too_long";
    public const string PasswordContainsNul = "invalid_input.password_contains_nul";
    public const string PasswordNotWellFormed = "invalid_input.password_not_well_formed";

    // UnsupportedEnvironment
    public const string Argon2idUnavailable = "environment.argon2id_unavailable";
}
