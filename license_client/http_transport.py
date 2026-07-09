from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import requests


def is_loopback_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def request(method: str, url: str, *, requests_module=requests, **kwargs):
    method_name = method.lower()
    if is_loopback_url(url):
        session = requests_module.Session()
        session.trust_env = False
        return session.request(method_name, url, **kwargs)
    return getattr(requests_module, method_name)(url, **kwargs)
