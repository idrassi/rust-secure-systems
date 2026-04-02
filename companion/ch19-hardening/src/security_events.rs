pub const AUTH_SUCCESS: &str = "auth.success";
pub const AUTH_FAILURE: &str = "auth.failure";
pub const AUTH_LOCKOUT: &str = "auth.lockout";
pub const AUTH_TOKEN_REFRESH: &str = "auth.token_refresh";

pub const ACCESS_GRANTED: &str = "access.granted";
pub const ACCESS_DENIED: &str = "access.denied";
pub const PRIVILEGE_ESCALATION_ATTEMPT: &str = "access.privilege_escalation";

pub const INPUT_REJECTED: &str = "input.rejected";
pub const INPUT_SIZE_EXCEEDED: &str = "input.size_exceeded";
pub const MALFORMED_REQUEST: &str = "input.malformed";

pub const RATE_LIMIT_EXCEEDED: &str = "rate_limit.exceeded";
pub const CONNECTION_LIMIT_EXCEEDED: &str = "rate_limit.connections";

pub const TLS_HANDSHAKE_FAILED: &str = "tls.handshake_failed";
pub const TLS_CERTIFICATE_INVALID: &str = "tls.cert_invalid";
pub const CRYPTO_OPERATION_FAILED: &str = "crypto.operation_failed";

pub const MEMORY_PRESSURE: &str = "resource.memory_pressure";
pub const TASK_TIMEOUT: &str = "resource.task_timeout";
