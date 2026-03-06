"""
Attack Engine - Attack execution engine
"""

import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

from llm_attack_lab.monitoring.metrics import get_metrics_collector
from llm_attack_lab.monitoring.logger import get_logger

# Import OTelManager for Prometheus export
try:
    from llm_attack_lab.monitoring.otel import get_otel_manager, init_telemetry
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    get_otel_manager = None
    init_telemetry = None

# Import SecurityMetricsCollector for advanced security metrics
try:
    from llm_attack_lab.monitoring.security_metrics import get_security_metrics
    SECURITY_METRICS_AVAILABLE = True
except ImportError:
    SECURITY_METRICS_AVAILABLE = False
    get_security_metrics = None


console = Console()
metrics = get_metrics_collector()
logger = get_logger("attack_engine")

# Initialize OTel for Prometheus export
_otel_manager: Optional[Any] = None
_security_metrics: Optional[Any] = None


def _get_otel_manager():
    """Get or initialize OTel manager for metrics export"""
    global _otel_manager
    if _otel_manager is None and OTEL_AVAILABLE:
        try:
            _otel_manager = init_telemetry()
            logger.debug("OTel manager initialized for attack engine")
        except Exception as e:
            logger.warning(f"Could not initialize OTel manager: {e}")
    return _otel_manager


def _get_security_metrics_collector():
    """Get or initialize security metrics collector"""
    global _security_metrics
    if _security_metrics is None and SECURITY_METRICS_AVAILABLE:
        try:
            _security_metrics = get_security_metrics()
            logger.debug("Security metrics collector initialized for attack engine")
        except Exception as e:
            logger.warning(f"Could not initialize security metrics: {e}")
    return _security_metrics


class AttackPhase(Enum):
    """Attack phases"""
    RECONNAISSANCE = "reconnaissance"
    PREPARATION = "preparation"
    EXECUTION = "execution"
    EXPLOITATION = "exploitation"
    ANALYSIS = "analysis"


@dataclass
class AttackResult:
    """Attack result"""
    success: bool
    attack_type: str
    payload: str
    response: str
    metadata: Dict = field(default_factory=dict)
    execution_time: float = 0.0
    defenses_bypassed: List[str] = field(default_factory=list)
    detection_status: str = "unknown"


class AttackEngine:
    """
    LLM attack execution engine.

    Manages the complete lifecycle of an attack:
    - Reconnaissance
    - Payload preparation
    - Execution
    - Results analysis
    """

    def __init__(self, llm_simulator):
        self.llm = llm_simulator
        self.results: List[AttackResult] = []
        self.current_phase: Optional[AttackPhase] = None
        self.observers: List[Callable] = []
        self.metrics = get_metrics_collector()
        self.logger = get_logger("attack_engine")

    def add_observer(self, callback: Callable):
        """Adds an observer for attack events"""
        self.observers.append(callback)

    def notify_observers(self, event: str, data: Dict):
        """Notifies observers of an event"""
        for observer in self.observers:
            observer(event, data)

    def execute_attack(
        self,
        attack_type: str,
        payloads: List[str],
        verbose: bool = True
    ) -> List[AttackResult]:
        """
        Executes a series of attacks with the given payloads.

        Args:
            attack_type: Attack type
            payloads: List of payloads to test
            verbose: Show details

        Returns:
            List of attack results
        """
        results = []

        if verbose:
            console.print(Panel(
                f"[bold red][ATK] Launching attack: {attack_type}[/]\n"
                f"[yellow]Payloads to test: {len(payloads)}[/]",
                title="Attack Engine",
                border_style="red"
            ))

        # Log attack start
        self.logger.log_attack_start(
            attack_type=attack_type,
            payload_count=len(payloads),
            security_level=self.llm.config.security_level.name
        )

        # Reconnaissance phase
        self._phase_reconnaissance(verbose)

        # Execution phase
        for i, payload in enumerate(payloads, 1):
            if verbose:
                console.print(f"\n[cyan][>] Payload {i}/{len(payloads)}:[/]")
                console.print(f"[dim]{payload[:100]}{'...' if len(payload) > 100 else ''}[/]")

            start_time = time.time()

            # Execute attack
            response, metadata = self.llm.process_input(payload)
            execution_time = time.time() - start_time

            # Analyze result
            result = AttackResult(
                success=metadata.get("compromised", False),
                attack_type=attack_type,
                payload=payload,
                response=response,
                metadata=metadata,
                execution_time=execution_time,
                defenses_bypassed=self._identify_bypassed_defenses(metadata),
                detection_status="detected" if metadata.get("attacks_detected") else "undetected"
            )

            results.append(result)
            self.results.append(result)

            # Record metrics (internal collector)
            self.metrics.record_attack(
                attack_type=attack_type,
                success=result.success,
                detected=result.detection_status == "detected",
                duration=execution_time
            )

            # Record metrics to Prometheus via OTelManager
            otel = _get_otel_manager()
            if otel:
                otel.record_attack(
                    attack_type=attack_type,
                    success=result.success,
                    detected=result.detection_status == "detected",
                    duration=execution_time
                )

            # Record security metrics for advanced monitoring
            sec_metrics = _get_security_metrics_collector()
            if sec_metrics:
                # Record prompt injection score based on detection
                injection_score = 0.9 if result.detection_status == "detected" else 0.3
                sec_metrics.record_prompt_injection_score(
                    score=injection_score,
                    model_name="llm-simulator",
                    detection_method="rule_based"
                )
                # Record API query for rate limiting tracking
                sec_metrics.record_api_query(
                    user_id="attack_engine",
                    ip_address="local",
                    endpoint=f"/attack/{attack_type}"
                )
                # Record security alert if attack was detected
                if result.detection_status == "detected":
                    sec_metrics.record_security_alert(
                        alert_type=attack_type,
                        severity="high" if result.success else "medium",
                        pattern="llm"
                    )

            # Log attack result
            self.logger.log_attack_result(
                attack_type=attack_type,
                success=result.success,
                detected=result.detection_status == "detected",
                duration=execution_time
            )

            if verbose:
                self._display_result(result)

            # Notify observers
            self.notify_observers("attack_executed", {
                "result": result,
                "index": i,
                "total": len(payloads)
            })

            time.sleep(0.5)  # Pause for visualization

        # Analysis phase
        if verbose:
            self._display_summary(results)

        return results

    def _phase_reconnaissance(self, verbose: bool):
        """Reconnaissance phase"""
        self.current_phase = AttackPhase.RECONNAISSANCE

        if verbose:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "[yellow][SCAN] Scanning target system...",
                    total=100
                )
                for _ in range(100):
                    time.sleep(0.01)
                    progress.update(task, advance=1)

            status = self.llm.get_status()
            console.print(Panel(
                f"[green][+] Target identified:[/] {status['model']}\n"
                f"[green][+] Security level:[/] {status['security_level']}\n"
                f"[green][+] Defenses active:[/] {'Yes' if status['defense_active'] else 'No'}",
                title="Reconnaissance",
                border_style="green"
            ))

    def _identify_bypassed_defenses(self, metadata: Dict) -> List[str]:
        """Identifies defenses that were bypassed"""
        bypassed = []
        if metadata.get("compromised"):
            defenses = metadata.get("defenses_triggered", [])
            if not defenses:
                bypassed.append("no_defenses_triggered")
            elif metadata.get("compromised"):
                bypassed.extend(defenses)
        return bypassed

    def _display_result(self, result: AttackResult):
        """Displays attack result"""
        if result.success:
            status = "[bold green][+] SUCCESS[/]"
            border_style = "green"
        else:
            status = "[bold red][-] FAILED[/]"
            border_style = "red"

        detection = (
            "[yellow][!] Detected[/]" if result.detection_status == "detected"
            else "[green][+] Undetected[/]"
        )

        content = (
            f"Status: {status}\n"
            f"Detection: {detection}\n"
            f"Time: {result.execution_time:.3f}s\n\n"
            f"[bold]Response:[/]\n{result.response[:200]}{'...' if len(result.response) > 200 else ''}"
        )

        console.print(Panel(content, title="[OUT] Result", border_style=border_style))

    def _display_summary(self, results: List[AttackResult]):
        """Displays attack summary"""
        console.print("\n")

        table = Table(
            title="Attack Campaign Summary",
            show_header=True,
            header_style="bold magenta"
        )

        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        total = len(results)
        successful = sum(1 for r in results if r.success)
        detected = sum(1 for r in results if r.detection_status == "detected")
        avg_time = sum(r.execution_time for r in results) / total if total > 0 else 0

        table.add_row("Total attacks", str(total))
        table.add_row("Successful attacks", f"{successful} ({successful/total*100:.1f}%)" if total > 0 else "0")
        table.add_row("Detected attacks", f"{detected} ({detected/total*100:.1f}%)" if total > 0 else "0")
        table.add_row("Average time", f"{avg_time:.3f}s")

        console.print(table)

        # Security evaluation
        if successful == 0:
            verdict = "[bold green][SECURE] SYSTEM SECURED[/]"
        elif successful < total / 2:
            verdict = "[bold yellow][WARN] VULNERABILITIES DETECTED[/]"
        else:
            verdict = "[bold red][PWNED] SYSTEM COMPROMISED[/]"

        console.print(Panel(verdict, title="Verdict", border_style="bold"))


class BaseAttack(ABC):
    """Base class for attacks"""

    name: str = "Base Attack"
    description: str = "Attack description"
    category: str = "unknown"
    severity: str = "unknown"

    def __init__(self):
        from llm_attack_lab.core.llm_simulator import LLMSimulator
        self.llm = LLMSimulator()
        self.engine = AttackEngine(self.llm)
        self.payloads: List[str] = []

    @abstractmethod
    def get_payloads(self) -> List[str]:
        """Returns payloads for this attack"""
        pass

    @abstractmethod
    def get_educational_content(self) -> Dict:
        """Returns educational content about this attack"""
        pass

    def run_simulation(self, security_level=None):
        """Executes the attack simulation"""
        from llm_attack_lab.core.llm_simulator import SecurityLevel

        console.print(Panel(
            f"[bold]{self.name}[/]\n\n"
            f"{self.description}\n\n"
            f"[yellow]Category:[/] {self.category}\n"
            f"[red]Severity:[/] {self.severity}",
            title="[ATK] Attack Simulation",
            border_style="red"
        ))

        # Display educational content
        edu = self.get_educational_content()
        console.print(Panel(
            edu.get("explanation", ""),
            title="[DOC] Explanation",
            border_style="blue"
        ))

        # Execute at different security levels
        levels = [SecurityLevel.NONE, SecurityLevel.MEDIUM, SecurityLevel.HIGH]
        if security_level:
            levels = [security_level]

        for level in levels:
            console.print(f"\n[bold cyan]━━━ Testing with security: {level.name} ━━━[/]")
            self.llm.reset()
            self.llm.set_security_level(level)
            payloads = self.get_payloads()
            self.engine.execute_attack(self.name, payloads)

        # Display recommended defenses
        console.print(Panel(
            "\n".join(f"* {d}" for d in edu.get("defenses", [])),
            title="[DEF] Recommended Defenses",
            border_style="green"
        ))
