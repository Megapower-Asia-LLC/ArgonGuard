"""Reason code 常數（權威來源：spec/reason-codes.json，字串必須 bit-identical）。"""

# MalformedHash
NOT_PHC = "malformed.not_phc"
BAD_BASE64 = "malformed.bad_base64"
PARAMS_OUT_OF_ORDER = "malformed.params_out_of_order"
ENCODED_TOO_LONG = "malformed.encoded_too_long"

# UnsupportedAlgorithm
UNSUPPORTED_ALGORITHM = "unsupported.algorithm"

# PolicyViolation
BELOW_OWASP_FRONTIER = "policy_violation.below_owasp_frontier"
M_ABOVE_CEILING = "policy_violation.m_above_ceiling"
T_ABOVE_CEILING = "policy_violation.t_above_ceiling"
SALT_LENGTH_OUT_OF_RANGE = "policy_violation.salt_length_out_of_range"
TAG_LENGTH_OUT_OF_RANGE = "policy_violation.tag_length_out_of_range"
P_NOT_ONE = "policy_violation.p_not_one"
MISSING_VERSION = "policy_violation.missing_version"
UNSUPPORTED_VERSION = "policy_violation.unsupported_version"
KEYID_NOT_ALLOWED = "policy_violation.keyid_not_allowed"
DATA_NOT_ALLOWED = "policy_violation.data_not_allowed"

# InvalidInput
PASSWORD_EMPTY = "invalid_input.password_empty"
PASSWORD_TOO_LONG = "invalid_input.password_too_long"
PASSWORD_CONTAINS_NUL = "invalid_input.password_contains_nul"
PASSWORD_NOT_WELL_FORMED = "invalid_input.password_not_well_formed"

# UnsupportedEnvironment
ARGON2ID_UNAVAILABLE = "environment.argon2id_unavailable"
