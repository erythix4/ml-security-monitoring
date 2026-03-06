#!/usr/bin/env python3
"""
Main entry point for the LLM Attack Simulation Lab
"""

import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from llm_attack_lab.cli.interactive import InteractiveLab
from llm_attack_lab.attacks import ATTACK_REGISTRY


console = Console()


def display_banner():
    """Displays the lab banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ██╗     ██╗     ███╗   ███╗     █████╗ ████████╗████████╗ ║
    ║     ██║     ██║     ████╗ ████║    ██╔══██╗╚══██╔══╝╚══██╔══╝ ║
    ║     ██║     ██║     ██╔████╔██║    ███████║   ██║      ██║    ║
    ║     ██║     ██║     ██║╚██╔╝██║    ██╔══██║   ██║      ██║    ║
    ║     ███████╗███████╗██║ ╚═╝ ██║    ██║  ██║   ██║      ██║    ║
    ║     ╚══════╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝    ║
    ║                                                               ║
    ║              LLM ATTACK SIMULATION LAB                        ║
    ║                                                               ║
    ║     Educational Platform for LLM Security Research           ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def display_attack_menu():
    """Displays the available attacks menu"""
    table = Table(
        title="Available Attacks",
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold magenta"
    )

    table.add_column("ID", style="cyan", width=5)
    table.add_column("Attack", style="green", width=25)
    table.add_column("Description", style="white", width=45)
    table.add_column("Risk", style="red", width=10)

    attacks = [
        ("1", "Prompt Injection", "Malicious prompt injection", "[!] Critical"),
        ("2", "Data Poisoning", "Training data corruption", "[!] High"),
        ("3", "Jailbreak", "Bypassing restrictions", "[!] Critical"),
        ("4", "Model Extraction", "Model extraction", "[!] High"),
        ("5", "Membership Inference", "Training data detection", "[.] Medium"),
    ]

    for attack in attacks:
        table.add_row(*attack)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="LLM Attack Simulation Lab - Educational LLM Security Platform"
    )

    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Launch interactive CLI mode"
    )

    parser.add_argument(
        "--web", "-w",
        action="store_true",
        help="Launch web dashboard"
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Port for web server (default: 8081, or WEB_SERVER_PORT)"
    )

    parser.add_argument(
        "--attack", "-a",
        choices=list(ATTACK_REGISTRY.keys()),
        help="Execute a specific attack"
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Execute a complete demonstration"
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available attacks"
    )

    args = parser.parse_args()

    display_banner()

    if args.list:
        display_attack_menu()
        return

    if args.web:
        from llm_attack_lab.web.app import run_web_server
        console.print("\n[bold green][WEB] Starting web server...[/]")
        run_web_server(port=args.port)
        return

    if args.attack:
        console.print(f"\n[bold yellow][ATK] Executing attack: {args.attack}[/]")
        attack_class = ATTACK_REGISTRY[args.attack]
        attack = attack_class()
        attack.run_simulation()
        return

    if args.demo:
        console.print("\n[bold green][DEMO] Demo mode[/]")
        lab = InteractiveLab()
        lab.run_demo()
        return

    # Interactive mode by default
    console.print("\n[bold green][START] Starting interactive mode...[/]\n")
    lab = InteractiveLab()
    lab.run()


if __name__ == "__main__":
    main()
