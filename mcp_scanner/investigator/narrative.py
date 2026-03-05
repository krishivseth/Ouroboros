from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown


def render_narrative_terminal(narrative: str) -> None:
    """Render the attack narrative as rich markdown in the terminal."""
    console = Console()
    console.print()
    console.rule("[bold red]Attack Narrative[/bold red]")
    console.print()
    console.print(Markdown(narrative))
    console.print()


def write_narrative_file(narrative: str, output_path: str) -> None:
    """Write the attack narrative to a markdown file."""
    Path(output_path).write_text(narrative + "\n", encoding="utf-8")
