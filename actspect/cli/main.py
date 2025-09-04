# Copyright (c) 2025 Axonius Solutions Ltd.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Main CLI entry point for ActSpect.
"""

import sys
import time
import click
from rich.console import Console
from rich.align import Align

from .. import __version__
from .commands import cli
from ..logging_config import configure_logging
from ..utils.system_utils import SystemUtils

console = Console()


def display_logo():
    """Display ActSpect ASCII art logo."""
    console.clear()

    logo = r"""
    █████╗  ██████╗████████╗███████╗██████╗ ███████╗ ██████╗████████╗
   ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝
   ███████║██║        ██║   ███████╗██████╔╝█████╗  ██║        ██║   
   ██╔══██║██║        ██║   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   
   ██║  ██║╚██████╗   ██║   ███████║██║     ███████╗╚██████╗   ██║   
   ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   
    """

    console.print(Align.center(logo, style="bold cyan"))
    time.sleep(1.0)
    console.clear()


def main():
    """Main entry point for ActSpect CLI."""
    try:
        # Display logo
        display_logo()

        # Check dependencies
        if not SystemUtils.check_dependencies():
            console.print(
                "[bold red]Error:[/bold red] Missing dependencies. "
                "Please ensure all required dependencies are installed."
            )
            sys.exit(1)

        # Configure default logging
        configure_logging(verbose=False)

        # Run CLI
        cli()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
