from enum import Enum


class LoginStatus(str, Enum):
    SUCCESS = "success"
    ALREADY_ONLINE = "already_online"
    INVALID_CREDENTIALS = "invalid_credentials"
    AUTH_FAILED = "auth_failed"
    INVALID_PORTAL_PARAMETER = "invalid_portal_parameter"
    IP_NOT_ONLINE = "ip_not_online"
    NOT_CAMPUS_NETWORK = "not_campus_network"
    AUTH_SERVICE_UNAVAILABLE = "auth_service_unavailable"
    TIMEOUT = "timeout"
    UNKNOWN_ERROR = "unknown_error"
    LOGOUT_SUCCESS = "logout_success"
    LOGOUT_FAILED = "logout_failed"
    LOGOUT_NOT_ONLINE = "logout_not_online"
    LOGOUT_INVALID_SESSION = "logout_invalid_session"
    LOGOUT_PORTAL_UNREACHABLE = "logout_portal_unreachable"
    LOGOUT_UNKNOWN_RESPONSE = "logout_unknown_response"
