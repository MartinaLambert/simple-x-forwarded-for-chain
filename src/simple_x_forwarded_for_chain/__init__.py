"""simple-x-forwarded-for-chain: parse and filter X-Forwarded-For header chains.

Re-exports the public API from :mod:`simple_x_forwarded_for_chain.core`.
"""
from .core import ChainResult, parse_x_forwarded_for

__all__ = ["ChainResult", "parse_x_forwarded_for"]
