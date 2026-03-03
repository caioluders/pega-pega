import logging
import sys
from pathlib import Path

import click

from . import __version__
from .config import Config
from .server import run_server


@click.command()
@click.option("--config", "-c", type=click.Path(), default=None, help="Path to config YAML file")
@click.option("--bind", "-b", default=None, help="IP to bind all listeners (default: 0.0.0.0)")
@click.option("--domain", "-d", default=None, help="Base domain for subdomain tracking")
@click.option("--response-ip", "-r", default=None, help="IP to return in DNS responses (auto-detect if not set)")
@click.option("--dashboard-port", default=None, type=int, help="Web dashboard port (default: 8443)")
@click.option("--db", default=None, help="SQLite database path")
@click.option("--no-dashboard", is_flag=True, default=False, help="Disable web dashboard")
@click.option("--protocols", "-p", default=None, help="Comma-separated list of protocols to enable (default: all)")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose logging")
@click.option("--update", is_flag=True, default=False, help="Update pega-pega to the latest version and exit")
@click.option("--version", is_flag=True, default=False, help="Show version and exit")
def main(config, bind, domain, response_ip, dashboard_port, db, no_dashboard, protocols, verbose, update, version):
    """Pega-Pega: Multi-protocol request logger/catcher.

    Listens on 14 common protocols and logs all incoming requests.
    Displays captured requests in a rich terminal UI and optional web dashboard.
    """
    if version:
        click.echo(f"pega-pega v{__version__}")
        sys.exit(0)

    if update:
        _do_update()
        return

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
    )

    cfg = Config.load(Path(config) if config else None)

    # Override config with CLI args
    if bind:
        cfg.bind_ip = bind
    if domain:
        cfg.domain = domain
    if response_ip:
        cfg.response_ip = response_ip
    if dashboard_port is not None:
        cfg.dashboard_port = dashboard_port
    if db:
        cfg.db_path = db
    if no_dashboard:
        cfg.no_dashboard = True

    # Filter protocols if specified
    if protocols:
        enabled = {p.strip().lower() for p in protocols.split(",")}
        for name, pc in cfg.protocols.items():
            pc.enabled = name in enabled

    run_server(cfg)


def _do_update():
    from .updater import perform_update, UpdateError

    click.echo(click.style("PEGA-PEGA", fg="cyan", bold=True) + " Self-Update")
    click.echo()

    try:
        result = perform_update()
    except UpdateError as e:
        click.echo(click.style(f"[-] Update failed: {e}", fg="red"))
        sys.exit(1)

    if result.already_up_to_date:
        click.echo(click.style(f"[+] Already up to date (v{result.old_version})", fg="green"))
    else:
        click.echo(click.style(f"[+] {result.old_version} → {result.new_version}", fg="green"))
        if result.restarted:
            click.echo(click.style("[+] Service restarted", fg="green"))
        else:
            click.echo(click.style("[!] No systemd service found — restart manually", fg="yellow"))
