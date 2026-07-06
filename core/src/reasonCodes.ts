/**
 * Reason code 常數。字串必須與 spec/reason-codes.json bit-identical
 * （conformance 測試以 reject 向量逐筆斷言）。
 */
export const ReasonCodes = {
  // MalformedHash
  NotPhc: "malformed.not_phc",
  BadBase64: "malformed.bad_base64",
  ParamsOutOfOrder: "malformed.params_out_of_order",
  EncodedTooLong: "malformed.encoded_too_long",

  // UnsupportedAlgorithm
  UnsupportedAlgorithm: "unsupported.algorithm",

  // PolicyViolation
  BelowOwaspFrontier: "policy_violation.below_owasp_frontier",
  MAboveCeiling: "policy_violation.m_above_ceiling",
  TAboveCeiling: "policy_violation.t_above_ceiling",
  SaltLengthOutOfRange: "policy_violation.salt_length_out_of_range",
  TagLengthOutOfRange: "policy_violation.tag_length_out_of_range",
  PNotOne: "policy_violation.p_not_one",
  MissingVersion: "policy_violation.missing_version",
  UnsupportedVersion: "policy_violation.unsupported_version",
  KeyidNotAllowed: "policy_violation.keyid_not_allowed",
  DataNotAllowed: "policy_violation.data_not_allowed",

  // InvalidInput
  PasswordEmpty: "invalid_input.password_empty",
  PasswordTooLong: "invalid_input.password_too_long",
  PasswordContainsNul: "invalid_input.password_contains_nul",
  PasswordNotWellFormed: "invalid_input.password_not_well_formed",

  // UnsupportedEnvironment
  Argon2idUnavailable: "environment.argon2id_unavailable",
} as const;
