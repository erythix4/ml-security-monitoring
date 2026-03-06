"""
Structured Logging Module

Provides comprehensive structured logging for the LLM Attack Lab
with support for multiple output formats and log levels.
"""

import logging
import json
import sys
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
import threading


class LogLevel(Enum):
    """Log severity levels"""
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    SECURITY = 55  # Custom level for security events


@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: str
    level: str
    message: str
    component: str = "lab"
    event_type: str = "general"
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    attack_type: Optional[str] = None
    security_level: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    stack_trace: Optional[str] = None

    def to_dict(self) -> Dict:
        result = asdict(self)
        # Remove None values
        return {k: v for k, v in result.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_text(self) -> str:
        parts = [
            f"[{self.timestamp}]",
            f"[{self.level}]",
            f"[{self.component}]",
        ]
        if self.event_type != "general":
            parts.append(f"[{self.event_type}]")
        if self.correlation_id:
            parts.append(f"[{self.correlation_id[:8]}]")
        parts.append(self.message)
        if self.metadata:
            parts.append(f"| {json.dumps(self.metadata)}")
        return " ".join(parts)


class LogFormatter:
    """Format log entries"""

    @staticmethod
    def format_text(entry: LogEntry) -> str:
        return entry.to_text()

    @staticmethod
    def format_json(entry: LogEntry) -> str:
        return entry.to_json()


class LogHandler:
    """Base log handler"""

    def emit(self, entry: LogEntry):
        raise NotImplementedError


class ConsoleHandler(LogHandler):
    """Console log handler with optional color output"""

    # Brighter, more readable colors for terminal output
    COLORS = {
        "DEBUG": "\033[96m",     # Bright Cyan - easier to read
        "INFO": "\033[92m",      # Bright Green - more visible
        "WARNING": "\033[93m",   # Bright Yellow - stands out
        "ERROR": "\033[91m",     # Bright Red - attention-grabbing
        "CRITICAL": "\033[95m",  # Bright Magenta - distinct
        "SECURITY": "\033[91;1m",  # Bold Bright Red - maximum visibility
        "RESET": "\033[0m",
    }

    def __init__(self, use_colors: bool = True, output_format: str = "text"):
        self.use_colors = use_colors
        self.output_format = output_format

    def emit(self, entry: LogEntry):
        if self.output_format == "json":
            output = LogFormatter.format_json(entry)
        else:
            output = LogFormatter.format_text(entry)

        if self.use_colors:
            color = self.COLORS.get(entry.level, "")
            reset = self.COLORS["RESET"]
            output = f"{color}{output}{reset}"

        print(output, file=sys.stderr)


class FileHandler(LogHandler):
    """File log handler"""

    def __init__(self, filepath: str, output_format: str = "json"):
        self.filepath = Path(filepath)
        self.output_format = output_format
        self._lock = threading.Lock()
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, entry: LogEntry):
        if self.output_format == "json":
            output = LogFormatter.format_json(entry)
        else:
            output = LogFormatter.format_text(entry)

        with self._lock:
            with open(self.filepath, "a") as f:
                f.write(output + "\n")


class MemoryHandler(LogHandler):
    """In-memory log handler for testing and debugging"""

    def __init__(self, max_entries: int = 1000):
        self.entries: List[LogEntry] = []
        self.max_entries = max_entries
        self._lock = threading.Lock()

    def emit(self, entry: LogEntry):
        with self._lock:
            self.entries.append(entry)
            if len(self.entries) > self.max_entries:
                self.entries = self.entries[-self.max_entries:]

    def get_entries(self, level: Optional[LogLevel] = None,
                    component: Optional[str] = None,
                    event_type: Optional[str] = None,
                    limit: int = 100) -> List[LogEntry]:
        """Get filtered log entries"""
        with self._lock:
            entries = self.entries.copy()

        if level:
            entries = [e for e in entries if e.level == level.name]
        if component:
            entries = [e for e in entries if e.component == component]
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]

        return entries[-limit:]

    def clear(self):
        with self._lock:
            self.entries.clear()


class LabLogger:
    """
    Main logger for LLM Attack Lab.

    Provides structured logging with support for:
    - Multiple output handlers (console, file, memory)
    - Structured log entries with metadata
    - Correlation IDs for request tracing
    - Security-specific logging
    - Attack and defense event logging
    """

    def __init__(self, component: str = "lab", level: LogLevel = LogLevel.INFO):
        self.component = component
        self.level = level
        self.handlers: List[LogHandler] = []
        self._correlation_id: Optional[str] = None
        self._session_id: Optional[str] = None
        self._lock = threading.RLock()

    def add_handler(self, handler: LogHandler):
        """Add a log handler"""
        self.handlers.append(handler)

    def remove_handler(self, handler: LogHandler):
        """Remove a log handler"""
        if handler in self.handlers:
            self.handlers.remove(handler)

    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for request tracing"""
        self._correlation_id = correlation_id

    def set_session_id(self, session_id: str):
        """Set session ID"""
        self._session_id = session_id

    def _should_log(self, level: LogLevel) -> bool:
        """Check if message should be logged based on level"""
        return level.value >= self.level.value

    def _create_entry(self, level: LogLevel, message: str,
                     event_type: str = "general", **kwargs) -> LogEntry:
        """Create a log entry"""
        return LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level.name,
            message=message,
            component=self.component,
            event_type=event_type,
            correlation_id=self._correlation_id,
            session_id=self._session_id,
            metadata=kwargs.get("metadata", {}),
            attack_type=kwargs.get("attack_type"),
            security_level=kwargs.get("security_level"),
            stack_trace=kwargs.get("stack_trace"),
        )

    def _emit(self, entry: LogEntry):
        """Emit log entry to all handlers"""
        with self._lock:
            for handler in self.handlers:
                try:
                    handler.emit(entry)
                except Exception:
                    pass

    def log(self, level: LogLevel, message: str, event_type: str = "general", **kwargs):
        """Log a message at specified level"""
        if self._should_log(level):
            entry = self._create_entry(level, message, event_type, **kwargs)
            self._emit(entry)

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.log(LogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self.log(LogLevel.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.log(LogLevel.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        self.log(LogLevel.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.log(LogLevel.CRITICAL, message, **kwargs)

    def security(self, message: str, **kwargs):
        """Log security event"""
        self.log(LogLevel.SECURITY, message, event_type="security", **kwargs)

    # Specialized logging methods
    def log_attack_start(self, attack_type: str, payload_count: int, security_level: str):
        """Log attack simulation start"""
        self.info(
            f"Attack simulation started: {attack_type}",
            event_type="attack_start",
            attack_type=attack_type,
            security_level=security_level,
            metadata={"payload_count": payload_count},
        )

    def log_attack_result(self, attack_type: str, success: bool, detected: bool, duration: float):
        """Log attack result"""
        self.info(
            f"Attack result: {attack_type} - {'SUCCESS' if success else 'FAILED'}",
            event_type="attack_result",
            attack_type=attack_type,
            metadata={
                "success": success,
                "detected": detected,
                "duration_seconds": round(duration, 3),
            },
        )

    def log_defense_action(self, defense_type: str, action: str,
                          threat_level: str, input_sample: str = ""):
        """Log defense action"""
        level = LogLevel.WARNING if action == "block" else LogLevel.INFO
        self.log(
            level,
            f"Defense action: {defense_type} - {action}",
            event_type="defense_action",
            metadata={
                "defense_type": defense_type,
                "action": action,
                "threat_level": threat_level,
                "input_sample": input_sample[:100] if input_sample else "",
            },
        )

    def log_security_event(self, event: str, threat_type: str,
                          severity: str, details: Dict = None):
        """Log security event"""
        self.security(
            f"Security event: {event}",
            metadata={
                "threat_type": threat_type,
                "severity": severity,
                "details": details or {},
            },
        )

    def log_session_start(self, session_id: str, mode: str):
        """Log session start"""
        self._session_id = session_id
        self.info(
            f"Session started: {mode}",
            event_type="session_start",
            metadata={"mode": mode},
        )

    def log_session_end(self, stats: Dict = None):
        """Log session end"""
        self.info(
            "Session ended",
            event_type="session_end",
            metadata={"stats": stats or {}},
        )


# Global logger instance
_global_logger: Optional[LabLogger] = None


def get_logger(component: str = "lab") -> LabLogger:
    """Get or create the global logger"""
    global _global_logger
    if _global_logger is None:
        _global_logger = LabLogger(component=component)
        # Add default console handler
        _global_logger.add_handler(ConsoleHandler(use_colors=True))
    return _global_logger


def configure_logging(level: LogLevel = LogLevel.INFO,
                     console: bool = True,
                     file_path: Optional[str] = None,
                     json_format: bool = False) -> LabLogger:
    """Configure the global logger"""
    global _global_logger
    _global_logger = LabLogger(level=level)

    if console:
        handler = ConsoleHandler(
            use_colors=True,
            output_format="json" if json_format else "text"
        )
        _global_logger.add_handler(handler)

    if file_path:
        handler = FileHandler(
            filepath=file_path,
            output_format="json" if json_format else "text"
        )
        _global_logger.add_handler(handler)

    return _global_logger
