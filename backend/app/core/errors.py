from enum import StrEnum


class ConfigurationErrorCode(StrEnum):
    CONFIG_FETCH_FAILED = "CONFIG_FETCH_FAILED"
    CONFIG_PARSE_FAILED = "CONFIG_PARSE_FAILED"
    SNAPSHOT_ALREADY_EXISTS = "SNAPSHOT_ALREADY_EXISTS"
    SNAPSHOT_PERSIST_FAILED = "SNAPSHOT_PERSIST_FAILED"
    SNAPSHOT_INTEGRITY_FAILED = "SNAPSHOT_INTEGRITY_FAILED"
    VENDOR_DETECTION_FAILED = "VENDOR_DETECTION_FAILED"
    UNSUPPORTED_VENDOR = "UNSUPPORTED_VENDOR"
    PARSER_NOT_FOUND = "PARSER_NOT_FOUND"


class ConfigurationPipelineError(RuntimeError):
    def __init__(self, code: ConfigurationErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
