def extract_subdomain(host: str, base_domain: str) -> str:
    """Extract subdomain from a hostname given the base domain.

    >>> extract_subdomain("foo.bar.pega.local", "pega.local")
    'foo.bar'
    >>> extract_subdomain("pega.local", "pega.local")
    ''
    >>> extract_subdomain("other.com", "pega.local")
    'other.com'
    """
    host = host.lower().split(":")[0]  # strip port
    base = base_domain.lower()
    if host == base:
        return ""
    if host.endswith("." + base):
        return host[: -(len(base) + 1)]
    return host
