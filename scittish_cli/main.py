#!/usr/bin/env python3
"""
scittish-cli - Command-line client for scittish SCITT signing service.

Usage:
    scittish-cli set server <url>     Configure the scittish server
    scittish-cli set subject <subj>   Set subject in local .scittish file
    scittish-cli push <file|sha256:x> Push a file or hash for signing
"""

import argparse
import sys

from . import __version__
from .config import set_server, set_subject, GlobalConfig, LocalConfig, fetch_server_properties
from .push import push


def cmd_set(args) -> int:
    """Handle the 'set' command."""
    if args.key == "server":
        try:
            set_server(args.value)
            return 0
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    elif args.key == "subject":
        set_subject(args.value)
        return 0
    else:
        print(f"Unknown configuration key: {args.key}", file=sys.stderr)
        print("Valid keys: server, subject", file=sys.stderr)
        return 1


def cmd_push(args) -> int:
    """Handle the 'push' command."""
    return push(
        target=args.target,
        subject=args.subject,
        no_prompt=args.no_prompt,
        show_receipt=args.show_receipt,
    )


def cmd_status(args) -> int:
    """Show current configuration status."""
    global_config = GlobalConfig.load()
    local_config = LocalConfig.load()
    
    print("Global configuration (~/.config/scittish/config.json):")
    if global_config.server_uri:
        print(f"  Server URI:     {global_config.server_uri}")
        print(f"  SCITT Ledger:   {global_config.scitt_url}")
        if global_config.certificate_chain:
            chain_lines = global_config.certificate_chain.count("-----BEGIN CERTIFICATE-----")
            print(f"  Cert chain:     {chain_lines} certificate(s)")
    else:
        print("  (not configured)")
    
    print()
    print("Local configuration (.scittish):")
    if local_config.subject:
        print(f"  Subject:        {local_config.subject}")
    else:
        print("  (not configured)")
    
    # Fetch live server properties
    if global_config.server_uri:
        print()
        try:
            properties = fetch_server_properties(global_config.server_uri)
            print(f"Server properties ({global_config.server_uri}/properties):")
            print(f"  SCITT URL:      {properties.get('scitt_url', '(unknown)')}")
            
            chain = properties.get("certificate_chain", "")
            if chain:
                cert_count = chain.count("-----BEGIN CERTIFICATE-----")
                print(f"  Cert chain:     {cert_count} certificate(s)")
            
            resolvers = properties.get("subject_resolvers", [])
            if resolvers:
                names = ", ".join(r.get("name", "?") for r in resolvers)
                print(f"  Resolvers:      {names}")
            
            indexers = properties.get("indexers", [])
            for idx in indexers:
                enabled = "enabled" if idx.get("enabled") else "disabled"
                registry = idx.get("registry", "")
                namespace = idx.get("namespace", "")
                print(f"  OCI indexer:    {enabled} ({registry}/{namespace})")
        except RuntimeError as e:
            print(f"  (server unreachable: {e})")
    
    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="scittish-cli",
        description="Command-line client for scittish SCITT signing service",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # 'set' command
    set_parser = subparsers.add_parser(
        "set",
        help="Set configuration values",
        description="Set global or local configuration values",
    )
    set_parser.add_argument(
        "key",
        choices=["server", "subject"],
        help="Configuration key to set (server=global, subject=local)",
    )
    set_parser.add_argument(
        "value",
        help="Value to set",
    )
    set_parser.set_defaults(func=cmd_set)
    
    # 'push' command
    push_parser = subparsers.add_parser(
        "push",
        help="Push a file or hash for signing",
        description="Push a file or hash to scittish for signing and get a receipt",
    )
    push_parser.add_argument(
        "target",
        help="File path or 'sha256:xxx' hash string",
    )
    push_parser.add_argument(
        "--subject",
        default=None,
        help="Override subject (empty string blanks it out)",
    )
    push_parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Skip confirmation prompt",
    )
    push_parser.add_argument(
        "--show-receipt",
        action="store_true",
        help="Pretty-print the receipt after receiving",
    )
    push_parser.set_defaults(func=cmd_push)
    
    # 'status' command
    status_parser = subparsers.add_parser(
        "status",
        help="Show current configuration",
        description="Display current global and local configuration",
    )
    status_parser.set_defaults(func=cmd_status)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
