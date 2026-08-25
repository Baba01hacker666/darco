from __future__ import annotations

import httpx


async def enumerate_subdomains_crtsh(
    domain: str, client: httpx.AsyncClient | None = None, timeout: float = 8.0
) -> list[str]:
    """Query Certificate Transparency logs via crt.sh to passively find subdomains."""
    subdomains: set[str] = set()
    own_client = False

    if client is None:
        client = httpx.AsyncClient(timeout=timeout, trust_env=False)
        own_client = True

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = await client.get(
            url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = str(entry.get("name_value", ""))
                for raw_name in name_value.split("\n"):
                    cleaned = raw_name.strip().lower()
                    cleaned = cleaned.removeprefix("*.")
                    if (
                        cleaned
                        and (cleaned == domain or cleaned.endswith(f".{domain}"))
                        and "@" not in cleaned
                        and " " not in cleaned
                    ):
                        subdomains.add(cleaned)
    except (httpx.HTTPError, ValueError, KeyError):
        # Degrade gracefully if crt.sh is unreachable or rate-limited
        pass
    finally:
        if own_client:
            await client.aclose()

    return sorted(subdomains)
