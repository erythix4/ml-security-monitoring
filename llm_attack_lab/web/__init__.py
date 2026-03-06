"""Web interface for LLM Attack Lab"""

__all__ = ["run_web_server"]


def __getattr__(name):
    """Lazy import to avoid RuntimeWarning when running as module."""
    if name == "run_web_server":
        from .app import run_web_server
        return run_web_server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
