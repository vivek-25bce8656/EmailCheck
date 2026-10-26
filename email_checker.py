"""
EmailCheck - Core Email Assessment & DNS Intelligence Engine
Provides evidence-based email syntax and DNS/MX routing analysis.
Classifies each address into one of three user-facing categories:
- Likely delivered
- Likely to bounce
- Unknown
"""
import re
import time
import threading
import concurrent.futures
from typing import Dict, List, Optional, Tuple, Any
import dns.resolver
import dns.exception
import dns.name

# RFC 5321 & 5322 constraints
MAX_EMAIL_LENGTH = 254
MAX_LOCAL_LENGTH = 64
MAX_DOMAIN_LENGTH = 253

# Primary User-Facing Classification Categories
CATEGORY_LIKELY_DELIVERED = "Likely delivered"
CATEGORY_LIKELY_TO_BOUNCE = "Likely to bounce"
CATEGORY_UNKNOWN = "Unknown"

# Technical DNS & Routing Status Indicators
DNS_STATUS_ACTIVE_MX = "Active MX record(s) detected"
DNS_STATUS_FALLBACK = "Implicit host routing fallback (A/AAAA)"
DNS_STATUS_NULL_MX = "RFC 7505 Null MX (declares no email acceptance)"
DNS_STATUS_NO_ROUTING = "No MX or fallback host (A/AAAA) records found"
DNS_STATUS_NXDOMAIN = "Domain not found (NXDOMAIN)"
DNS_STATUS_TIMEOUT = "DNS query timed out"
DNS_STATUS_ERROR = "DNS temporary resolution / network failure"
DNS_STATUS_NOT_EVALUATED = "Not evaluated (syntax error)"

# Backward-Compatibility Status Aliases
STATUS_MAIL_CONFIG = CATEGORY_LIKELY_DELIVERED
STATUS_NO_MX = CATEGORY_LIKELY_TO_BOUNCE
STATUS_NULL_MX = CATEGORY_LIKELY_TO_BOUNCE
STATUS_DOMAIN_NOT_FOUND = CATEGORY_LIKELY_TO_BOUNCE
STATUS_INVALID_FORMAT = CATEGORY_LIKELY_TO_BOUNCE
STATUS_UNABLE_TO_VERIFY = CATEGORY_UNKNOWN
STATUS_UNKNOWN = CATEGORY_UNKNOWN

# CSS / Badge mappings
STATUS_BADGES = {
    CATEGORY_LIKELY_DELIVERED: {
        "css": "status-success",
        "badge": "Likely delivered",
        "type": "success",
    },
    CATEGORY_LIKELY_TO_BOUNCE: {
        "css": "status-danger",
        "badge": "Likely to bounce",
        "type": "danger",
    },
    CATEGORY_UNKNOWN: {
        "css": "status-neutral",
        "badge": "Unknown",
        "type": "neutral",
    },
}

# Legacy Badge Lookups for Backward Compatibility
STATUS_BADGES.update({
    "Mail configuration detected": STATUS_BADGES[CATEGORY_LIKELY_DELIVERED],
    "No MX record detected": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE],
    "Null MX - Does not accept email": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE],
    "Domain not found": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE],
    "Invalid format": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE],
    "Unable to verify": STATUS_BADGES[CATEGORY_UNKNOWN],
})

LOCAL_PART_PATTERN = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
)
DOMAIN_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

# Batch Processing Limits
DEFAULT_BATCH_LIMIT = 100
MAX_BATCH_LIMIT = 500
ALLOWED_BATCH_LIMITS = (100, 500)

# Thread-safe bounded in-memory DNS cache with TTL
_DNS_CACHE: Dict[str, Tuple[float, Any]] = {}
_DNS_CACHE_MAX_SIZE = 2500
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


def validate_domain_syntax(domain: str) -> Tuple[bool, str, str]:
    """
    Validate domain syntax against standard DNS host naming rules and IDN/Punycode.
    Returns: (is_valid, ascii_domain, error_reason)
    """
    if not domain or not isinstance(domain, str):
        return False, "", "Empty or null domain portion provided."

    raw_domain = domain.strip().lower()
    if not raw_domain:
        return False, "", "Empty domain portion provided."

    # Check for domain literals [IP]
    if raw_domain.startswith("[") and raw_domain.endswith("]"):
        return (
            False,
            raw_domain,
            "Domain literals (IP addresses in brackets) are not supported for public mail routing.",
        )

    # Handle Internationalized Domain Names (IDN / Punycode)
    try:
        ascii_domain = raw_domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return (
            False,
            raw_domain,
            "Domain contains non-ASCII characters that cannot be converted to valid IDN/Punycode.",
        )

    if len(ascii_domain) > MAX_DOMAIN_LENGTH:
        return (
            False,
            ascii_domain,
            f"Domain exceeds maximum length of {MAX_DOMAIN_LENGTH} characters.",
        )

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        return (
            False,
            ascii_domain,
            "Domain must contain at least a name and a top-level domain (TLD).",
        )

    for label in labels:
        if not label:
            return (
                False,
                ascii_domain,
                "Domain contains an empty label or consecutive periods.",
            )
        if len(label) > 63:
            return (
                False,
                ascii_domain,
                f"Domain label '{label}' exceeds maximum 63 characters.",
            )
        if not DOMAIN_LABEL_PATTERN.fullmatch(label):
            return (
                False,
                ascii_domain,
                f"Domain label '{label}' contains invalid characters or starts/ends with a hyphen.",
            )

    # TLD validation
    tld = labels[-1]
    if len(tld) < 2 or tld.isdigit():
        return (
            False,
            ascii_domain,
            "Top-level domain (TLD) is invalid or purely numeric.",
        )

    return True, ascii_domain, ""


def validate_email_syntax(email: str) -> Tuple[bool, str, str, str]:
    """
    Validate email address syntax against RFC-oriented specifications (RFC 5321 / RFC 5322 constraints).
    Returns: (is_valid, local_part, domain_part, error_reason)
    """
    if not email or not isinstance(email, str):
        return False, "", "", "Empty or null address provided."

    email = email.strip()
    if not email:
        return False, "", "", "Empty or null address provided."

    if len(email) > MAX_EMAIL_LENGTH:
        return (
            False,
            "",
            "",
            f"Email address exceeds maximum RFC length of {MAX_EMAIL_LENGTH} characters (length: {len(email)}).",
        )

    if "@" not in email:
        return False, "", "", "Email address is missing the '@' delimiter."

    if email.count("@") > 1:
        return (
            False,
            "",
            "",
            "Email address contains multiple '@' delimiters (invalid syntax).",
        )

    # Check for whitespace inside the email address
    if any(c.isspace() for c in email):
        return (
            False,
            "",
            "",
            "Email address contains invalid whitespace characters.",
        )

    parts = email.split("@")
    if len(parts) != 2:
        return False, "", "", "Email address format is invalid."

    local_part, domain_part = parts

    if not local_part:
        return (
            False,
            "",
            domain_part,
            "Email address is missing the local user portion before '@'.",
        )

    if not domain_part:
        return (
            False,
            local_part,
            "",
            "Email address is missing the domain portion after '@'.",
        )

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
        return (
            False,
            local_part,
            domain_part,
            "Local part cannot start or end with a period.",
        )

    if ".." in local_part:
        return (
            False,
            local_part,
            domain_part,
            "Local part cannot contain consecutive periods ('..').",
        )

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
    is_domain_valid, ascii_domain, domain_err = validate_domain_syntax(domain_part)
    if not is_domain_valid:
        return False, local_part, domain_part, domain_err

    return True, local_part, ascii_domain, ""


def resolve_domain_mail_config(domain: str) -> Dict[str, Any]:
    """
    Check DNS records for mail configuration.
    1. Look up MX records with a 2.5s timeout.
    2. Explicitly handle RFC 7505 Null MX (exchange '.') records declaring no email acceptance.
    3. If no MX record exists, query A and AAAA records as fallback (RFC 5321 Sec 5.1).
    4. Distinguish confirmed absence of mail routing from temporary timeouts or resolution errors.
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
                if cached_result.get("classification") != CATEGORY_UNKNOWN
                else _DNS_CACHE_FAILURE_TTL
            )
            if now - cached_time < ttl:
                return cached_result

    result: Dict[str, Any] = {
        "classification": CATEGORY_UNKNOWN,
        "status": CATEGORY_UNKNOWN,
        "css": STATUS_BADGES[CATEGORY_UNKNOWN]["css"],
        "badge": STATUS_BADGES[CATEGORY_UNKNOWN]["badge"],
        "dns_status": DNS_STATUS_ERROR,
        "reason": "Assessment inconclusive.",
        "limitation": "Available evidence cannot reliably determine mail routing.",
        "mx_records": [],
        "primary_mx": None,
        "has_mx": False,
        "has_fallback": False,
    }

    try:
        # Step 1: MX record lookup
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=2.5)

        # Check for RFC 7505 Null MX record
        # A Null MX record consists of a single MX with target "."
        # explicitly declaring that the domain does not accept email.
        is_null_mx = False
        null_mx_pref = 0
        for rdata in mx_answers:
            ex_obj = getattr(rdata, "exchange", None)
            ex_str = str(ex_obj).strip()
            if ex_str in (".", "") or ex_obj == dns.name.root:
                is_null_mx = True
                null_mx_pref = getattr(rdata, "preference", 0)
                break

        if is_null_mx:
            result = {
                "classification": CATEGORY_LIKELY_TO_BOUNCE,
                "status": CATEGORY_LIKELY_TO_BOUNCE,
                "css": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["css"],
                "badge": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["badge"],
                "dns_status": DNS_STATUS_NULL_MX,
                "reason": (
                    "Domain publishes a Null MX record (RFC 7505) with target '.', "
                    "explicitly declaring that it does not accept email. "
                    "Implicit host routing fallback (A/AAAA) does not apply."
                ),
                "limitation": (
                    "Domain explicitly rejects incoming email; messages sent to this address will bounce."
                ),
                "mx_records": [f". (priority {null_mx_pref})"],
                "primary_mx": f". (priority {null_mx_pref})",
                "has_mx": False,
                "has_fallback": False,
            }
        else:
            mx_list = []
            for rdata in sorted(mx_answers, key=lambda x: getattr(x, "preference", 0)):
                pref = getattr(rdata, "preference", 0)
                exchange = str(getattr(rdata, "exchange", "")).rstrip(".")
                mx_list.append(f"{exchange} (priority {pref})")

            primary = mx_list[0] if mx_list else None
            result = {
                "classification": CATEGORY_LIKELY_DELIVERED,
                "status": CATEGORY_LIKELY_DELIVERED,
                "css": STATUS_BADGES[CATEGORY_LIKELY_DELIVERED]["css"],
                "badge": STATUS_BADGES[CATEGORY_LIKELY_DELIVERED]["badge"],
                "dns_status": f"Active MX server: {primary}",
                "reason": (
                    f"Domain publishes active mail exchange (MX) server(s) ({primary}). "
                    "Mail routing is configured at the domain level."
                ),
                "limitation": (
                    "DNS records verify domain mail-routing infrastructure only; "
                    "individual mailbox existence cannot be confirmed without sending an email."
                ),
                "mx_records": mx_list,
                "primary_mx": primary,
                "has_mx": True,
                "has_fallback": False,
            }

    except dns.resolver.NXDOMAIN:
        result = {
            "classification": CATEGORY_LIKELY_TO_BOUNCE,
            "status": CATEGORY_LIKELY_TO_BOUNCE,
            "css": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["css"],
            "badge": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["badge"],
            "dns_status": DNS_STATUS_NXDOMAIN,
            "reason": "The domain does not exist in DNS (NXDOMAIN); mail cannot be routed.",
            "limitation": "Nonexistent domain prevents mail delivery; messages will bounce.",
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
                "classification": CATEGORY_UNKNOWN,
                "status": CATEGORY_UNKNOWN,
                "css": STATUS_BADGES[CATEGORY_UNKNOWN]["css"],
                "badge": STATUS_BADGES[CATEGORY_UNKNOWN]["badge"],
                "dns_status": DNS_STATUS_TIMEOUT,
                "reason": "DNS check timed out while querying host A records.",
                "limitation": (
                    "Temporary DNS timeout. Delivery outcome cannot be reliably determined "
                    "under current network conditions."
                ),
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
                    "classification": CATEGORY_UNKNOWN,
                    "status": CATEGORY_UNKNOWN,
                    "css": STATUS_BADGES[CATEGORY_UNKNOWN]["css"],
                    "badge": STATUS_BADGES[CATEGORY_UNKNOWN]["badge"],
                    "dns_status": DNS_STATUS_TIMEOUT,
                    "reason": "DNS check timed out while querying host AAAA records.",
                    "limitation": (
                        "Temporary DNS timeout. Delivery outcome cannot be reliably determined "
                        "under current network conditions."
                    ),
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
                "classification": CATEGORY_LIKELY_DELIVERED,
                "status": CATEGORY_LIKELY_DELIVERED,
                "css": STATUS_BADGES[CATEGORY_LIKELY_DELIVERED]["css"],
                "badge": STATUS_BADGES[CATEGORY_LIKELY_DELIVERED]["badge"],
                "dns_status": f"Implicit host fallback (RFC 5321): {fallback_hosts[0]}",
                "reason": (
                    "No dedicated MX record found, but domain resolves to an active host IP address "
                    f"({fallback_hosts[0]}). Implicit mail routing fallback is active under RFC 5321."
                ),
                "limitation": (
                    "Implicit fallback routing detected at domain level; individual mailbox "
                    "existence cannot be confirmed by DNS alone without sending an email."
                ),
                "mx_records": [f"Implicit host record: {fallback_hosts[0]}"],
                "primary_mx": fallback_hosts[0],
                "has_mx": False,
                "has_fallback": True,
            }
        else:
            result = {
                "classification": CATEGORY_LIKELY_TO_BOUNCE,
                "status": CATEGORY_LIKELY_TO_BOUNCE,
                "css": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["css"],
                "badge": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["badge"],
                "dns_status": DNS_STATUS_NO_ROUTING,
                "reason": (
                    "Domain exists, but has no MX or fallback host records (A/AAAA) configured for mail routing."
                ),
                "limitation": (
                    "Confirmed absence of usable mail routing; mail transfer agents cannot deliver "
                    "messages to this domain."
                ),
                "mx_records": [],
                "primary_mx": None,
                "has_mx": False,
                "has_fallback": False,
            }

    except dns.exception.Timeout:
        result = {
            "classification": CATEGORY_UNKNOWN,
            "status": CATEGORY_UNKNOWN,
            "css": STATUS_BADGES[CATEGORY_UNKNOWN]["css"],
            "badge": STATUS_BADGES[CATEGORY_UNKNOWN]["badge"],
            "dns_status": DNS_STATUS_TIMEOUT,
            "reason": "DNS lookup timed out while querying mail exchange records.",
            "limitation": (
                "Temporary DNS timeout. This is not proof that the domain cannot receive email."
            ),
            "mx_records": [],
            "primary_mx": None,
            "has_mx": False,
            "has_fallback": False,
        }

    except (dns.exception.DNSException, OSError, ValueError):
        result = {
            "classification": CATEGORY_UNKNOWN,
            "status": CATEGORY_UNKNOWN,
            "css": STATUS_BADGES[CATEGORY_UNKNOWN]["css"],
            "badge": STATUS_BADGES[CATEGORY_UNKNOWN]["badge"],
            "dns_status": DNS_STATUS_ERROR,
            "reason": "DNS check failed due to a temporary resolution or network error.",
            "limitation": (
                "Temporary network or resolver error. This is not proof that the domain cannot receive email."
            ),
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
    Classifies the address into exactly one of three user-facing categories:
    - Likely delivered
    - Likely to bounce
    - Unknown
    Never attempts SMTP mailbox probes or sends emails.
    """
    clean_email = email.strip()

    is_valid, local_part, domain_part, syntax_error = validate_email_syntax(clean_email)
    if not is_valid:
        syntax_desc = syntax_error or "The email address format violates RFC standards."
        return {
            "email": clean_email,
            "classification": CATEGORY_LIKELY_TO_BOUNCE,
            "status": CATEGORY_LIKELY_TO_BOUNCE,
            "css": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["css"],
            "badge": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["badge"],
            "reason": f"Invalid email syntax: {syntax_desc}",
            "syntax_status": f"Invalid syntax: {syntax_desc}",
            "dns_status": DNS_STATUS_NOT_EVALUATED,
            "limitation": "Malformed syntax causes mail servers and transfer agents to reject the address prior to delivery.",
            "domain": domain_part or "N/A",
            "primary_mx": "None",
            "mx_records": [],
            "is_deliverable_claim": False,
        }

    dns_info = resolve_domain_mail_config(domain_part)

    return {
        "email": clean_email,
        "classification": dns_info["classification"],
        "status": dns_info["status"],
        "css": dns_info["css"],
        "badge": dns_info["badge"],
        "reason": dns_info["reason"],
        "syntax_status": "Valid RFC syntax",
        "dns_status": dns_info.get("dns_status", "N/A"),
        "limitation": dns_info.get(
            "limitation",
            "DNS records confirm domain mail-routing capability only; individual mailbox existence cannot be proven without sending an email.",
        ),
        "domain": domain_part,
        "primary_mx": dns_info.get("primary_mx") or "None",
        "mx_records": dns_info.get("mx_records", []),
        "is_deliverable_claim": False,
    }


def assess_batch(emails: List[str], max_workers: int = 16) -> List[Dict[str, Any]]:
    """
    Perform high-throughput, bounded concurrent assessments for a batch of email addresses.
    1. Validates syntax for all addresses in memory.
    2. Identifies unique domains among syntactically valid addresses to avoid duplicate queries.
    3. Leverages thread-safe in-memory caching for domains resolved previously.
    4. Concurrently resolves uncached unique domains using bounded worker threads.
    5. Assembles and returns assessments in the strict original input order.
    """
    if not emails:
        return []

    results: List[Optional[Dict[str, Any]]] = [None] * len(emails)
    valid_address_domain: Dict[int, Tuple[str, str]] = {}
    domains_to_resolve: set = set()

    # Step 1: Rapid syntax evaluation
    for idx, raw_email in enumerate(emails):
        clean_email = raw_email.strip() if isinstance(raw_email, str) else ""
        is_valid, local_part, domain_part, syntax_error = validate_email_syntax(clean_email)

        if not is_valid:
            syntax_desc = syntax_error or "The email address format violates RFC standards."
            results[idx] = {
                "email": clean_email,
                "classification": CATEGORY_LIKELY_TO_BOUNCE,
                "status": CATEGORY_LIKELY_TO_BOUNCE,
                "css": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["css"],
                "badge": STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["badge"],
                "reason": f"Invalid email syntax: {syntax_desc}",
                "syntax_status": f"Invalid syntax: {syntax_desc}",
                "dns_status": DNS_STATUS_NOT_EVALUATED,
                "limitation": "Malformed syntax causes mail servers and transfer agents to reject the address prior to delivery.",
                "domain": domain_part or "N/A",
                "primary_mx": "None",
                "mx_records": [],
                "is_deliverable_claim": False,
            }
        else:
            valid_address_domain[idx] = (clean_email, domain_part)
            domains_to_resolve.add(domain_part)

    # Step 2: Concurrently resolve unique uncached domains with bounded worker pool
    domain_results: Dict[str, Dict[str, Any]] = {}
    now = time.time()

    uncached_domains: List[str] = []
    for dom in domains_to_resolve:
        with _CACHE_LOCK:
            if dom in _DNS_CACHE:
                cached_time, cached_res = _DNS_CACHE[dom]
                ttl = (
                    _DNS_CACHE_TTL
                    if cached_res.get("classification") != CATEGORY_UNKNOWN
                    else _DNS_CACHE_FAILURE_TTL
                )
                if now - cached_time < ttl:
                    domain_results[dom] = cached_res
                    continue
        uncached_domains.append(dom)

    if uncached_domains:
        effective_workers = min(len(uncached_domains), max(1, max_workers))
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
            future_to_dom = {
                executor.submit(resolve_domain_mail_config, d): d
                for d in uncached_domains
            }
            for fut in concurrent.futures.as_completed(future_to_dom):
                dom_name = future_to_dom[fut]
                try:
                    domain_results[dom_name] = fut.result()
                except Exception:
                    domain_results[dom_name] = {
                        "classification": CATEGORY_UNKNOWN,
                        "status": CATEGORY_UNKNOWN,
                        "css": STATUS_BADGES[CATEGORY_UNKNOWN]["css"],
                        "badge": STATUS_BADGES[CATEGORY_UNKNOWN]["badge"],
                        "dns_status": DNS_STATUS_ERROR,
                        "reason": "DNS resolution failed due to an unexpected worker error.",
                        "limitation": "Resolution inconclusive under current operating conditions.",
                        "mx_records": [],
                        "primary_mx": None,
                        "has_mx": False,
                        "has_fallback": False,
                    }

    # Step 3: Assemble results strictly in original input order
    for idx, (clean_email, domain_part) in valid_address_domain.items():
        dns_info = domain_results.get(domain_part)
        if not dns_info:
            dns_info = resolve_domain_mail_config(domain_part)

        results[idx] = {
            "email": clean_email,
            "classification": dns_info["classification"],
            "status": dns_info["status"],
            "css": dns_info["css"],
            "badge": dns_info["badge"],
            "reason": dns_info["reason"],
            "syntax_status": "Valid RFC syntax",
            "dns_status": dns_info.get("dns_status", "N/A"),
            "limitation": dns_info.get(
                "limitation",
                "DNS records confirm domain mail-routing capability only; individual mailbox existence cannot be proven without sending an email.",
            ),
            "domain": domain_part,
            "primary_mx": dns_info.get("primary_mx") or "None",
            "mx_records": dns_info.get("mx_records", []),
            "is_deliverable_claim": False,
        }

    return results  # type: ignore[return-value]


def aggregate_domain_insights(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group assessment results by domain to provide independent domain-level intelligence.
    Domain DNS assessment is completely decoupled from individual email syntax errors:
    a malformed address does not determine the DNS status of its domain.
    """
    domain_map: Dict[str, Dict[str, Any]] = {}
    domain_dns_found: Dict[str, Dict[str, Any]] = {}

    for item in results:
        raw_domain = item.get("domain", "N/A")
        if not raw_domain or raw_domain == "N/A":
            continue

        domain_key = raw_domain.strip().lower()

        if domain_key not in domain_map:
            domain_map[domain_key] = {
                "domain": domain_key,
                "address_count": 0,
                "addresses": [],
            }

        domain_map[domain_key]["address_count"] += 1
        domain_map[domain_key]["addresses"].append(item.get("email", ""))

        # Record DNS-assessed result if available and not a syntax failure
        if (
            domain_key not in domain_dns_found
            and "Invalid syntax" not in item.get("syntax_status", "")
        ):
            domain_dns_found[domain_key] = item

    insights: List[Dict[str, Any]] = []
    for domain_key, info in domain_map.items():
        if domain_key in domain_dns_found:
            dns_item = domain_dns_found[domain_key]
            info["classification"] = dns_item.get("classification", dns_item.get("status", CATEGORY_UNKNOWN))
            info["status"] = dns_item.get("status", dns_item.get("classification", CATEGORY_UNKNOWN))
            info["css"] = dns_item.get("css", "status-neutral")
            info["badge"] = dns_item.get("badge", "Unknown")
            info["dns_status"] = dns_item.get("dns_status", "N/A")
            info["primary_mx"] = dns_item.get("primary_mx", "None")
            info["mx_count"] = len(dns_item.get("mx_records", []))
            info["reason"] = dns_item.get("reason", "")
            info["limitation"] = dns_item.get("limitation", "")
        else:
            # If all addresses for this domain had syntax errors, perform DNS assessment
            # independently if domain syntax is valid
            is_valid_dom, ascii_dom, _ = validate_domain_syntax(domain_key)
            if is_valid_dom:
                dns_res = resolve_domain_mail_config(ascii_dom)
                info["classification"] = dns_res["classification"]
                info["status"] = dns_res["status"]
                info["css"] = dns_res["css"]
                info["badge"] = dns_res["badge"]
                info["dns_status"] = dns_res.get("dns_status", "N/A")
                info["primary_mx"] = dns_res.get("primary_mx") or "None"
                info["mx_count"] = len(dns_res.get("mx_records", []))
                info["reason"] = dns_res.get("reason", "")
                info["limitation"] = dns_res.get("limitation", "")
            else:
                info["classification"] = CATEGORY_LIKELY_TO_BOUNCE
                info["status"] = CATEGORY_LIKELY_TO_BOUNCE
                info["css"] = STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["css"]
                info["badge"] = STATUS_BADGES[CATEGORY_LIKELY_TO_BOUNCE]["badge"]
                info["dns_status"] = DNS_STATUS_NOT_EVALUATED
                info["primary_mx"] = "None"
                info["mx_count"] = 0
                info["reason"] = "Domain label syntax violates RFC specifications."
                info["limitation"] = "Invalid domain syntax prevents DNS resolution."

        insights.append(info)

    return insights
