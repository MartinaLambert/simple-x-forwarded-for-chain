"""Core parsing and filtering logic for X-Forwarded-For header chains."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence


@dataclass
class ChainResult:
    """Structured view of a parsed ``X-Forwarded-For`` header chain."""

    raw: str
    direct_address: Optional[str]
    proxy_addresses: List[str] = field(default_factory=list)
    all_addresses: List[str] = field(default_factory=list)


def _valid_token(token: str) -> bool:
    """Return True if *token* looks like a plausible IP address literal.

    Structural validation only: hex digits, dots, colons, and IPv6 brackets
    are permitted. This deliberately accepts bracketed IPv6 (e.g.
    ``[2001:db8::1]``) which :mod:`ipaddress` rejects.
    """
    if not token:
        return False
    for ch in token:
        if not (
            ch.isdigit()
            or ch in "abcdefABCDEF.:[]"
        ):
            return False
    return True


def parse_x_forwarded_for(header: Optional[str]) -> ChainResult:
    """Parse an ``X-Forwarded-For`` header into a :class:`ChainResult`.

    Empty or falsy headers yield a result with ``direct_address`` set to
    ``None`` and empty address lists. Malformed tokens are silently dropped.
    """
    raw = header if header is not None else ""
    if not header or not header.strip():
        return ChainResult(raw=raw, direct_address=None)

    parts = [p.strip() for p in header.split(",")]
    addresses = [p for p in parts if _valid_token(p)]

    if not addresses:
        return ChainResult(raw=raw, direct_address=None)

    direct = addresses[0]
    proxies = addresses[1:]
    return ChainResult(
        raw=raw,
        direct_address=direct,
        proxy_addresses=list(proxies),
        all_addresses=list(addresses),
    )


def untrusted_addresses(
    result: ChainResult, trusted_proxies: Sequence[str]
) -> List[str]:
    """Return the addresses that remain after trusted-proxy stripping.

    The chain is walked from the right: each address whose right-hand peer
    is a trusted proxy is stripped, and the walk stops at the first address
    whose right-hand peer is not trusted. The remaining addresses are
    returned in original left-to-right order.
    """
    addresses = list(result.all_addresses)
    if not addresses:
        return []

    trusted = set(trusted_proxies)
    index = len(addresses) - 1

    while index > 0 and addresses[index] in trusted:
        index -= 1

    return addresses[: index + 1]
