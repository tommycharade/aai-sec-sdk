"""Exceptions for programmer and configuration failures."""


class SecurityConfigurationError(ValueError):
    """Raised when a tool or runtime is configured with unsafe invariants."""


class DuplicateToolError(SecurityConfigurationError):
    """Raised when a tool name is registered more than once."""


class RuntimeStateError(RuntimeError):
    """Raised when the runtime cannot safely perform an operation."""
