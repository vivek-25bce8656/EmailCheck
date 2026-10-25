"""
EmailCheck - Core Email Assessment & DNS Intelligence Engine
Provides evidence-based email syntax and DNS/MX routing analysis.
"""
import re
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
import dns.resolver
import dns.exception

# RFC 5321 & 5322 constraints
MAX_EMAIL_LENGTH = 254
MAX_LOCAL_LENGTH = 64
MAX_DOMAIN_LENGTH = 253

# Result Categories
STATUS_MAIL_CONFIG = "Mail configuration detected"
STATUS_NO_MX = "No MX record detected"
STATUS_DOMAIN_NOT_FOUND = "Domain not found"
STATUS_INVALID_FORMAT = "Invalid format"
STATUS_UNABLE_TO_VERIFY = "Unable to verify"
STATUS_UNKNOWN = "Unknown"

# CSS / Badge mappings
STATUS_BADGES = {
    STATUS_MAIL_CONFIG: {"css": "status-success", "badge": "Mail Configured", "type": "valid"},
    STATUS_NO_MX: {"css": "status-warning", "badge": "No MX Record", "type": "warning"},
    STATUS_DOMAIN_NOT_FOUND: {"css": "status-danger", "badge": "Domain Not Found", "type": "danger"},
    STATUS_INVALID_FORMAT: {"css": "status-danger", "badge": "Invalid Format", "type": "danger"},
    STATUS_UNABLE_TO_VERIFY: {"css": "status-neutral", "badge": "Unable to Verify", "type": "neutral"},
    STATUS_UNKNOWN: {"css": "status-neutral", "badge": "Inconclusive", "type": "neutral"},
}

LOCAL_PART_PATTERN = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
DOMAIN_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# Thread-safe bounded in-memory DNS cache with TTL
_DNS_CACHE: Dict[str, Tuple[float, Any]] = {}
_DNS_CACHE_MAX_SIZE = 500
_DNS_CACHE_TTL = 300  # seconds for valid resolution
_DNS_CACHE_FAILURE_TTL = 15  # seconds for temporary errors/timeouts
_CACHE_LOCK = threading.Lock()


def clear_dns_cache() -> None:
    """Clear cached DNS results (thread-safe, useful for testing)."""
    with _CACHE_LOCK:
        _DNS_CACHE.clear()


def get_dns_cache_size() -> int:
    """Return number of cached domain entries."""
    with _CACHE_LOCK:
        return len(_DNS_CACHE)


def sanitize_csv_value(value: Any) -> str:
    """
    Sanitize values for CSV export to prevent spreadsheet formula injection
    (CSV Injection / Formula Injection) via =, +, -, @, tab, or carriage return.
    Also handles leading whitespace cases correctly.
    """
    if value is None:
        return ""
    text = str(value)
    trimmed = text.lstrip(" ")
    if trimmed and trimmed[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text.strip()


def validate_email_syntax(email: str) -> Tuple[bool, str, str, str]:
    """
    Validate email address syntax against RFC 5321 and RFC 5322 specifications.
    Returns: (is_valid, local_part, domain_part, error_reason)
    """
    if not email or not isinstance(email, str):
        return False, "", "", "Empty or null address provided."

    email = email.strip()

    if len(email) > MAX_EMAIL_LENGTH:
        return (
            False,
            "",
            "",
            f"Email address exceeds maximum RFC length of {MAX_EMAIL_LENGTH} characters (length: {len(email)}).",
        )

    if "@" not in email:
        return False, "", "", "Email address is missing the '@' delimiter."

    parts = email.rsplit("@", 1)
    if len(parts) != 2:
        return False, "", "", "Email address format is invalid."

    local_part, domain_part = parts

    if not local_part:
        return False, "", domain_part, "Email address is missing the local user portion before '@'."

    if not domain_part:
        return False, local_part, "", "Email address is missing the domain portion after '@'."

    # Check for domain literals [IP]
    if domain_part.startswith("[") and domain_part.endswith("]"):
        return (
            False,
            local_part,
            domain_part,
            "Domain literals (IP addresses in brackets) are not supported for public mail routing.",
        )

    # Local Part Length & Structure
    if len(local_part) > MAX_LOCAL_LENGTH:
        return (
            False,
            local_part,
            domain_part,
            f"Local part exceeds maximum length of {MAX_LOCAL_LENGTH} characters (length: {len(local_part)}).",
        )

    if local_part.startswith(".") or local_part.endswith("."):
        return False, local_part, domain_part, "Local part cannot start or end with a period."

    if ".." in local_part:
        return False, local_part, domain_part, "Local part cannot contain consecutive periods ('..')."

    # Check for non-ASCII in local part
    if any(ord(c) > 127 for c in local_part):
        return (
            False,
            local_part,
            domain_part,
            "Local mailbox portion contains non-ASCII characters (internationalized mailboxes require standard ASCII formatting or SMTPUTF8 support).",
        )

    if not LOCAL_PART_PATTERN.fullmatch(local_part):
        return False, local_part, domain_part, "Local part contains invalid characters."

    # Validate Domain Part & IDN Handling
    raw_domain = domain_part.strip().lower()

    # Handle Internationalized Domain Names (IDN / Punycode)
    try:
        ascii_domain = raw_domain.encode("idna").decode("ascii")
    except UnicodeError:
        return (
            False,
            local_part,
            domain_part,
            "Domain contains non-ASCII characters that cannot be converted to valid IDN/Punycode.",
        )

    if len(ascii_domain) > MAX_DOMAIN_LENGTH:
        return (
            False,
            local_part,
            domain_part,
            f"Domain exceeds maximum length of {MAX_DOMAIN_LENGTH} characters.",
        )

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        return False, local_part, domain_part, "Domain must contain at least a name and a top-level domain (TLD)."

    for label in labels:
        if not label:
            return False, local_part, domain_part, "Domain contains an empty label or consecutive periods."
        if len(label) > 63:
            return False, local_part, domain_part, f"Domain label '{label}' exceeds maximum 63 characters."
        if not DOMAIN_LABEL_PATTERN.fullmatch(label):
            return False, local_part, domain_part, f"Domain label '{label}' contains invalid characters or starts/ends with a hyphen."

    # TLD validation
    tld = labels[-1]
    if len(tld) < 2 or tld.isdigit():
        return False, local_part, domain_part, "Top-level domain (TLD) is invalid or purely numeric."

    return True, local_part, ascii_domain, ""


def resolve_domain_mail_config(domain: str) -> Dict[str, Any]:
    """
    Check DNS records for mail configuration.
    1. Look up MX records with a 2.5s timeout.
    2. If no MX record exists, query A and AAAA records as fallback (RFC 5321 Sec 5.1).
    3. Handles NXDOMAIN, NoAnswer, Timeout, and DNSException safely.
    Thread-safe with bounded in-memory caching.
    """
    domain = domain.strip().lower().rstrip(".")
    now = time.time()

    # Thread-safe Cache Read
    with _CACHE_LOCK:
        if domain in _DNS_CACHE:
            cached_time, cached_result = _DNS_CACHE[domain]
            ttl = (
                _DNS_CACHE_TTL
                if cached_result.get("status") != STATUS_UNABLE_TO_VERIFY
                else _DNS_CACHE_FAILURE_TTL
            )
            if now - cached_time < ttl:
                return cached_result

    result: Dict[str, Any] = {
        "status": STATUS_UNKNOWN,
        "css": "status-neutral",
        "badge": "Inconclusive",
        "reason": "Assessment inconclusive.",
        "mx_records": [],
        "primary_mx": None,
        "has_mx": False,
        "has_fallback": False,
    }

    try:
        # Step 1: MX record lookup
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=2.5)
        mx_list = []
        for rdata in sorted(mx_answers, key=lambda x: getattr(x, "preference", 0)):
            pref = getattr(rdata, "preference", 0)
            exchange = str(getattr(rdata, "exchange", "")).rstrip(".")
            mx_list.append(f"{exchange} (priority {pref})")

        primary = mx_list[0] if mx_list else None
        result = {
            "status": STATUS_MAIL_CONFIG,
            "css": STATUS_BADGES[STATUS_MAIL_CONFIG]["css"],
            "badge": STATUS_BADGES[STATUS_MAIL_CONFIG]["badge"],
            "reason": (
                "Domain has active mail exchange (MX) server(s) configured. "
                "Mail servers detected, but individual mailbox existence cannot be confirmed by DNS alone."
            ),
            "mx_records": mx_list,
            "primary_mx": primary,
            "has_mx": True,
            "has_fallback": False,
        }

    except dns.resolver.NXDOMAIN:
        result = {
            "status": STATUS_DOMAIN_NOT_FOUND,
            "css": STATUS_BADGES[STATUS_DOMAIN_NOT_FOUND]["css"],
            "badge": STATUS_BADGES[STATUS_DOMAIN_NOT_FOUND]["badge"],
            "reason": "The domain does not exist in DNS (NXDOMAIN).",
            "mx_records": [],
            "primary_mx": None,
            "has_mx": False,
            "has_fallback": False,
        }

    except dns.resolver.NoAnswer:
        # Step 2: Check for RFC 5321 fallback mail routing via A or AAAA records
        fallback_hosts = []
        try:
            a_answers = dns.resolver.resolve(domain, "A", lifetime=2.0)
            fallback_hosts.extend([str(rdata) for rdata in a_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.Timeout:
            result = {
                "status": STATUS_UNABLE_TO_VERIFY,
                "css": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["css"],
                "badge": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["badge"],
                "reason": "DNS check timed out while querying host A records.",
                "mx_records": [],
                "primary_mx": None,
                "has_mx": False,
                "has_fallback": False,
            }
            with _CACHE_LOCK:
                while len(_DNS_CACHE) >= _DNS_CACHE_MAX_SIZE:
                    oldest_key = next(iter(_DNS_CACHE))
                    _DNS_CACHE.pop(oldest_key, None)
                _DNS_CACHE[domain] = (now, result)
            return result
        except (dns.exception.DNSException, OSError, ValueError):
            pass

        # If no A records, check AAAA (IPv6) host records under RFC 5321
        if not fallback_hosts:
            try:
                aaaa_answers = dns.resolver.resolve(domain, "AAAA", lifetime=2.0)
                fallback_hosts.extend([str(rdata) for rdata in aaaa_answers])
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.exception.Timeout:
                result = {
                    "status": STATUS_UNABLE_TO_VERIFY,
                    "css": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["css"],
                    "badge": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["badge"],
                    "reason": "DNS check timed out while querying host AAAA records.",
                    "mx_records": [],
                    "primary_mx": None,
                    "has_mx": False,
                    "has_fallback": False,
                }
                with _CACHE_LOCK:
                    while len(_DNS_CACHE) >= _DNS_CACHE_MAX_SIZE:
                        oldest_key = next(iter(_DNS_CACHE))
                        _DNS_CACHE.pop(oldest_key, None)
                    _DNS_CACHE[domain] = (now, result)
                return result
            except (dns.exception.DNSException, OSError, ValueError):
                pass

        if fallback_hosts:
            result = {
                "status": STATUS_MAIL_CONFIG,
                "css": STATUS_BADGES[STATUS_MAIL_CONFIG]["css"],
                "badge": "Implicit Fallback",
                "reason": (
                    "No dedicated MX record found, but domain resolves to an active host IP address "
                    f"({fallback_hosts[0]}). Implicit mail routing fallback is active under RFC 5321."
                ),
                "mx_records": [f"Implicit host record: {fallback_hosts[0]}"],
                "primary_mx": fallback_hosts[0],
                "has_mx": False,
                "has_fallback": True,
            }
        else:
            result = {
                "status": STATUS_NO_MX,
                "css": STATUS_BADGES[STATUS_NO_MX]["css"],
                "badge": STATUS_BADGES[STATUS_NO_MX]["badge"],
                "reason": "Domain exists, but has no MX or fallback host records (A/AAAA) configured for mail routing.",
                "mx_records": [],
                "primary_mx": None,
                "has_mx": False,
                "has_fallback": False,
            }

    except dns.exception.Timeout:
        result = {
            "status": STATUS_UNABLE_TO_VERIFY,
            "css": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["css"],
            "badge": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["badge"],
            "reason": "DNS lookup timed out while querying mail exchange records.",
            "mx_records": [],
            "primary_mx": None,
            "has_mx": False,
            "has_fallback": False,
        }

    except (dns.exception.DNSException, OSError, ValueError):
        result = {
            "status": STATUS_UNABLE_TO_VERIFY,
            "css": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["css"],
            "badge": STATUS_BADGES[STATUS_UNABLE_TO_VERIFY]["badge"],
            "reason": "DNS check failed due to a temporary resolution or network error.",
            "mx_records": [],
            "primary_mx": None,
            "has_mx": False,
            "has_fallback": False,
        }

    # Thread-safe Bounded Cache Write
    with _CACHE_LOCK:
        while len(_DNS_CACHE) >= _DNS_CACHE_MAX_SIZE:
            oldest_key = next(iter(_DNS_CACHE))
            _DNS_CACHE.pop(oldest_key, None)
        _DNS_CACHE[domain] = (now, result)

    return result


def assess_email(email: str) -> Dict[str, Any]:
    """
    Perform a complete, evidence-based assessment of a single email address.
    Never attempts SMTP mailbox probes or sends emails.
    """
    clean_email = email.strip()

    is_valid, local_part, domain_part, syntax_error = validate_email_syntax(clean_email)
    if not is_valid:
        return {
            "email": clean_email,
            "status": STATUS_INVALID_FORMAT,
            "css": STATUS_BADGES[STATUS_INVALID_FORMAT]["css"],
            "badge": STATUS_BADGES[STATUS_INVALID_FORMAT]["badge"],
            "reason": syntax_error or "The email address format violates RFC standards.",
            "domain": domain_part or "N/A",
            "primary_mx": "None",
            "mx_records": [],
            "is_deliverable_claim": False,
        }

    dns_info = resolve_domain_mail_config(domain_part)

    return {
        "email": clean_email,
        "status": dns_info["status"],
        "css": dns_info["css"],
        "badge": dns_info["badge"],
        "reason": dns_info["reason"],
        "domain": domain_part,
        "primary_mx": dns_info.get("primary_mx") or "None",
        "mx_records": dns_info.get("mx_records", []),
        "is_deliverable_claim": False,
    }


def aggregate_domain_insights(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group assessment results by domain to provide domain-level intelligence.
    """
    domains: Dict[str, Dict[str, Any]] = {}

    for item in results:
        domain = item.get("domain", "N/A")
        if not domain or domain == "N/A":
            continue

        if domain not in domains:
            domains[domain] = {
                "domain": domain,
                "status": item["status"],
                "css": item["css"],
                "badge": item["badge"],
                "primary_mx": item.get("primary_mx", "None"),
                "mx_count": len(item.get("mx_records", [])),
                "address_count": 0,
                "addresses": [],
            }

        domains[domain]["address_count"] += 1
        domains[domain]["addresses"].append(item["email"])

    return list(domains.values())
