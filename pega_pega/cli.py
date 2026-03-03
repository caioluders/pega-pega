import logging
from pathlib import Path

import click

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
def main(config, bind, domain, response_ip, dashboard_port, db, no_dashboard, protocols, verbose):
    """Pega-Pega: Multi-protocol request logger/catcher.

    Listens on 14 common protocols and logs all incoming requests.
    Displays captured requests in a rich terminal UI and optional web dashboard.
    """
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
