# simple-x-forwarded-for-chain

Parse an `X-Forwarded-For` header chain, split it into the direct (leftmost) address and the proxy-originated addresses that follow, and apply trusted-proxy filtering from the right.

```python
from simple_x_forwarded_for_chain import parse_x_forwarded_for, ChainResult
from simple_x_forwarded_for_chain.core import untrusted_addresses

r = parse_x_forwarded_for("203.0.113.5, 198.51.100.1, 198.51.100.2")
# ChainResult(raw='203.0.113.5, 198.51.100.1, 198.51.100.2',
#             direct_address='203.0.113.5',
#             proxy_addresses=['198.51.100.1', '198.51.100.2'],
#             all_addresses=['203.0.113.5', '198.51.100.1', '198.51.100.2'])

remaining = untrusted_addresses(r, ["198.51.100.1", "198.51.100.2"])
# ['203.0.113.5']  -- the first address whose right-hand peer is not trusted
```

## Why this exists

When a request crosses one or more reverse proxies, the `X-Forwarded-For` header accumulates addresses left-to-right: the original client first, then each proxy that forwarded the request. To recover the real client address you need to know which of those addresses were inserted by proxies you control, and stop trusting at the first address inserted by a proxy you do not.

This library does only that. It does not integrate with any web framework, it does not consult socket peer addresses, and it does not validate that an address is routable. The trade-off is simplicity and zero dependencies: you bring the header string and the list of trusted proxy addresses, and the library gives you back a structured view and a filtered list.

## Edge you will hit

Address tokens are validated structurally, not via `ipaddress`, because real-world XFF values include bracketed IPv6 (`[2001:db8::1]`) which `ipaddress` rejects. The library accepts bracketed and bare IPv6 and passes them through unchanged; it is up to you to normalise them if your downstream consumer cares. Malformed tokens (anything containing characters outside hex digits, dots, colons, and brackets) are silently dropped from the chain rather than raising, because raising on a single bad hop would discard the rest of a otherwise useful header.

Trusted-proxy matching is an exact, case-sensitive string comparison. The chain is walked from the right: each address whose right-hand peer is trusted is stripped, and the walk stops at the first untrusted peer. The remaining list (which may contain more than one address when an untrusted proxy is in the middle of the chain) is returned in original left-to-right order.
