import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

HASH_REGEX = re.compile(
    r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$"
)


def normalize_value(value: str) -> str:
    """
    Normaliza a entrada do usuário.

    Exemplos:
    - https://example.com/path -> example.com
    - example.com:443 -> example.com
    - [2001:db8::1]:8080 -> 2001:db8::1
    - 2001:db8::1 -> 2001:db8::1
    """
    value = (value or "").strip()

    if not value:
        return ""

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc

    # IPv6 entre colchetes, ex.: [2001:db8::1]:8080
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")].lower()

    # Se tem mais de dois pontos, provavelmente é IPv6 puro.
    if value.count(":") > 1:
        return value.lower()

    # Remove path e porta para IPv4/domínio.
    value = value.split("/")[0]
    value = value.split(":")[0]

    return value.lower().rstrip(".")


def classify_indicator(value: str) -> str:
    """
    Classifica o indicador como:
    - ip
    - domain
    - hash
    """
    value = normalize_value(value)

    if not value:
        raise ValueError("Informe um indicador válido.")

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if HASH_REGEX.match(value):
        return "hash"

    if DOMAIN_REGEX.match(value):
        return "domain"

    raise ValueError(
        "Não foi possível classificar o indicador como IP, domínio ou hash."
    )