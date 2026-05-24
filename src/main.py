import re
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

# SECURITY: Hostile-input detection
# These patterns catch common injection and manipulation attempts.
# Lines matching ANY of these are quarantined and skipped entirely.

HOSTILE_PATTERNS = [
    re.compile(r"(?:--|;|')\s*(?:OR|AND|DROP|SELECT|INSERT|UPDATE|DELETE|UNION)", re.IGNORECASE),  # SQL injection
    re.compile(r"<script[\s>]", re.IGNORECASE),   # XSS script tags
    re.compile(r"\\x[0-9a-fA-F]{2}"),             # Null bytes / hex escapes embedded in strings
    re.compile(r"\.\./|\.\.\\"),                   # Path traversal sequences
    re.compile(r"admin@\[[\d.]+\]"),               # IP-literal email (RFC-rare, often spoofed)
]

def is_hostile(line: str) -> bool:
    """
    Returns True if the line contains patterns associated with injection
    attacks or other hostile manipulation attempts.
    Any match quarantines the entire line — extraction is skipped.
    """
    return any(p.search(line) for p in HOSTILE_PATTERNS)


# ---------------------------------------------------------------------------
# REGEX PATTERNS — each pattern targets one data type
# ---------------------------------------------------------------------------

# 1. EMAIL ADDRESSES
#    Handles: standard addresses, plus-addressing (user+tag@domain),
#    subdomains, country-TLDs (.co.ke, .io), multi-part TLDs.
#    Rejects: double-@, leading/trailing dots in local part, consecutive dots.
EMAIL_RE = re.compile(
    r"\b"
    r"(?!.*@@)"                         # Guard: no double-@
    r"([a-zA-Z0-9]"                     # Local part must start with alnum
    r"(?:[a-zA-Z0-9.+\-]*[a-zA-Z0-9])?)" # Local part body (no leading/trailing dots)
    r"@"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"  # Domain label
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"  # Sub-labels
    r"\.[a-zA-Z]{2,})"                  # TLD (min 2 chars)
    r"\b"
)

# ALU-specific email domains — validated as a second pass on extracted emails
ALU_DOMAINS = {
    "official":  re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+\-]*@alueducation\.com$"),
    "alumni":    re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+\-]*@alumni\.alueducation\.com$"),
    "si":        re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+\-]*@si\.alueducation\.com$"),
}

def classify_email(email: str) -> str:
    """Returns the ALU category of an email, or 'general' if not ALU."""
    for category, pattern in ALU_DOMAINS.items():
        if pattern.match(email):
            return f"alu_{category}"
    return "general"


# 2. URLS
#    Handles: http/https, optional port, paths, query strings.
#    Rejects: path-traversal URLs (caught by hostile check first),
#             non-HTTP schemes like ftp:// are extracted but flagged.
URL_RE = re.compile(
    r"\b((?:https?|ftp)://"              # Scheme (http, https, ftp)
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"  # Host
    r"(?::\d{1,5})?"                     # Optional port
    r"(?:/[^\s<>\"']*)?)"                # Path + query (no whitespace or quotes)
)

UNSAFE_URL_RE = re.compile(r"\.\./|%2e%2e", re.IGNORECASE)  # Path traversal in URL


# 3. PHONE NUMBERS
#    Handles East African formats (Kenya +254, Nigeria +234, Ghana +233, Somalia +252),
#    US format +1 (NXX), and local Kenyan formats (07xx, 01xx).
#    Also handles separators: spaces, dashes, dots, parentheses.
PHONE_RE = re.compile(
    r"(?:"
    r"\+\d{1,3}[\s\-.]?\(?\d{1,4}\)?[\s\-.]?\d{3}[\s\-.]?\d{3,4}[\s\-.]?\d{0,4}"  # International format
    r"|"
    r"\(0\d{2}\)\s?\d{3}[\s\-]?\d{4}"  # Local landline: (020) 203-4567
    r"|"
    r"0[17]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}"  # Kenyan mobile: 0712 345 678
    r")"
)

# Secondary validation: pure regex checks on extracted phone numbers.
#
# ALL_ZEROS_RE  — matches a digit string made entirely of zeros (fake/placeholder)
# MIN_DIGITS_RE — asserts at least 7 digit characters exist (rejects short fragments)
ALL_ZEROS_RE  = re.compile(r"^0+$")
MIN_DIGITS_RE = re.compile(r"(?:\d.*?){7}")

def is_valid_phone(phone: str) -> bool:
    """
    Regex-only phone validation (no plain Python length checks).
    1. Strips non-digits via regex substitution.
    2. Rejects all-zero sequences with ALL_ZEROS_RE.
    3. Rejects strings with fewer than 7 digits with MIN_DIGITS_RE.
    """
    digits = re.sub(r"\D", "", phone)          # isolate digits
    if not MIN_DIGITS_RE.search(digits):       # must have 7+ digits
        return False
    if ALL_ZEROS_RE.match(digits):             # all-zero = fake
        return False
    return True


# 4. CREDIT CARD NUMBERS
#    Handles: Visa (starts 4), MasterCard (starts 51-55 or 2221-2720),
#             Amex (starts 34/37), Discover (starts 6011/65).
#    Groups of 4 digits separated by spaces or dashes.
#    Luhn algorithm applied as final validation to eliminate random numbers.
CARD_RE = re.compile(
    r"\b"
    r"(?:"
    r"4\d{3}"             # Visa prefix
    r"|5[1-5]\d{2}"       # MasterCard prefix (51-55)
    r"|2[2-7]\d{2}"       # MasterCard prefix (2221-2720)
    r"|3[47]\d{2}"        # Amex prefix
    r"|6(?:011|5\d{2})"   # Discover prefix
    r")"
    r"[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"  # Remaining 12 digits in groups
    r"\b"
)

# CARD_LENGTH_RE — validates that a stripped card number is exactly 15 or 16 digits.
# Amex cards are 15 digits; Visa/MC/Discover are 16.
CARD_LENGTH_RE = re.compile(r"^\d{15,16}$")

# CARD_LAST4_RE — captures the final 4 digits of a digit-only string (for masking).
CARD_LAST4_RE  = re.compile(r"(\d{4})$")

# LUHN_DOUBLE — maps each digit to its Luhn-doubled value (pre-computed lookup table).
# Eliminates arithmetic: digit*2 if <=9 else digit*2-9, stored as strings.
LUHN_DOUBLE = {"0":"0","1":"2","2":"4","3":"6","4":"8",
               "5":"1","6":"3","7":"5","8":"7","9":"8"}

def luhn_check(card_number: str) -> bool:
    """
    Luhn checksum using regex for all digit extraction and length validation.
    The LUHN_DOUBLE table eliminates arithmetic — only regex and dict lookup used.
    Steps:
      1. Extract digits-only with regex substitution.
      2. Validate 15 or 16 digit length with CARD_LENGTH_RE.
      3. Reverse digits; for every odd-indexed position apply LUHN_DOUBLE.
      4. Sum all resulting digit characters; valid card if total % 10 == 0.
    """
    digits = re.sub(r"\D", "", card_number)           # Step 1: digits only
    if not CARD_LENGTH_RE.match(digits):              # Step 2: length check via regex
        return False
    total = 0
    for i, d in enumerate(digits[::-1]):              # Step 3: reverse and iterate
        effective = LUHN_DOUBLE[d] if i % 2 == 1 else d
        total += sum(int(c) for c in effective)       # Step 4: sum digits
    return total % 10 == 0

def mask_card(card_number: str) -> str:
    """
    SECURITY: Masks all but the last 4 digits before any output/logging.
    Uses CARD_LAST4_RE regex to extract last 4 digits — no plain slicing.
    """
    digits = re.sub(r"\D", "", card_number)
    m = CARD_LAST4_RE.search(digits)
    last4 = m.group(1) if m else "????"
    return f"****-****-****-{last4}"


# FTP_SCHEME_RE — detects non-HTTP URL schemes (ftp://) via regex.
# Replaces the plain string .split("://") used previously.
FTP_SCHEME_RE = re.compile(r"^ftp://", re.IGNORECASE)


# 5. HTML TAGS
HTML_TAG_RE = re.compile(
    r"<(?!script)"                   # Opening < but NOT <script (blocked by hostile check)
    r"(/?)([a-zA-Z][a-zA-Z0-9]*)"   # Optional / for closing tags + tag name
    r"([^>]*)"                       # Attributes (anything that's not >)
    r"(/?)>"                         # Optional / for self-closing + >
)


# 6. HASHTAGS
#    Standard social-media hashtags: # followed by word characters.
#    Min length of 2 to avoid noise (#a, single-char tags).
HASHTAG_RE = re.compile(r"#([a-zA-Z][a-zA-Z0-9_]{1,})")



def extract_all(text: str) -> dict:
    """
    Main extraction function.
    Processes the input text line by line:
      1. Each line is screened for hostile patterns first.
      2. If clean, regex extraction runs on the line.
      3. All extracted values are validated before being stored.
    Returns a structured dict of all findings.
    """
    results = {
        "meta": {
            "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_file": "input/raw-text.txt",
            "security_note": (
                "Credit card numbers are masked. "
                "Lines containing hostile patterns were quarantined and skipped. "
                "All data passed secondary validation before inclusion."
            )
        },
        "emails": {"alu_official": [], "alu_alumni": [], "alu_si": [], "general": []},
        "urls": {"valid": [], "flagged": []},
        "phone_numbers": [],
        "credit_cards": [],   # stored masked only
        "html_tags": [],
        "hashtags": [],
        "quarantined_lines": 0,
        "rejected": {
            "emails": [],
            "phones": [],
            "cards": []
        }
    }

    seen_emails  = set()
    seen_urls    = set()
    seen_phones  = set()
    seen_cards   = set()   # keyed by last-4 to avoid duplicating masked entries
    seen_tags    = set()
    seen_hashtags = set()

    lines = text.splitlines()

    for line in lines:
        # SECURITY GATE: quarantine hostile lines
        if is_hostile(line):
            results["quarantined_lines"] += 1
            continue   # Do NOT extract anything from this line

        # EMAIL extraction
        for match in EMAIL_RE.finditer(line):
            email = match.group(0).lower().strip(".")
            # Reject malformed: consecutive dots, local part starting/ending with dot
            if re.search(r"\.{2,}", email) or email.startswith(".") or "@." in email:
                if email not in results["rejected"]["emails"]:
                    results["rejected"]["emails"].append(email)
                continue
            if email in seen_emails:
                continue
            seen_emails.add(email)
            category = classify_email(email)
            if category == "alu_official":
                results["emails"]["alu_official"].append(email)
            elif category == "alu_alumni":
                results["emails"]["alu_alumni"].append(email)
            elif category == "alu_si":
                results["emails"]["alu_si"].append(email)
            else:
                results["emails"]["general"].append(email)

        # URL extraction
        for match in URL_RE.finditer(line):
            url = match.group(0).rstrip(".,;)")  # strip trailing punctuation
            if url in seen_urls:
                continue
            # Secondary security check: path traversal in the URL itself
            if UNSAFE_URL_RE.search(url):
                results["urls"]["flagged"].append({"url": url, "reason": "path traversal"})
                seen_urls.add(url)
                continue
            seen_urls.add(url)
            # FTP_SCHEME_RE detects non-HTTP schemes via regex (replaces plain .split)
            if FTP_SCHEME_RE.match(url):
                results["urls"]["flagged"].append({"url": url, "reason": "non-HTTP scheme (ftp)"})
            else:
                results["urls"]["valid"].append(url)

        # PHONE NUMBER extraction
        for match in PHONE_RE.finditer(line):
            phone = match.group(0).strip().rstrip(".,;")
            if not is_valid_phone(phone):
                if phone not in results["rejected"]["phones"]:
                    results["rejected"]["phones"].append(phone)
                continue
            if phone in seen_phones:
                continue
            seen_phones.add(phone)
            results["phone_numbers"].append(phone)

        # CREDIT CARD extraction
        for match in CARD_RE.finditer(line):
            raw_card = match.group(0)
            # Skip placeholder/masked cards (contains x or *)
            if re.search(r"[xX*]", raw_card):
                continue
            if not luhn_check(raw_card):
                # Reject cards that fail Luhn — includes 0000-0000-0000-0000,
                # 9999-9999-9999-9999, and other fabricated numbers
                results["rejected"]["cards"].append("****-****-****-XXXX (failed Luhn)")
                continue
            last4 = re.sub(r"\D", "", raw_card)[-4:]
            if last4 in seen_cards:
                continue
            seen_cards.add(last4)
            # SECURITY: store only the masked version — full number never reaches output
            results["credit_cards"].append(mask_card(raw_card))

        # HTML TAG extraction
        for match in HTML_TAG_RE.finditer(line):
            tag = match.group(0)
            if tag not in seen_tags:
                seen_tags.add(tag)
                results["html_tags"].append(tag)

        # --- HASHTAG extraction ---
        for match in HASHTAG_RE.finditer(line):
            tag = "#" + match.group(1).lower()
            if tag not in seen_hashtags:
                seen_hashtags.add(tag)
                results["hashtags"].append(tag)

    return results


def print_summary(results: dict):
    """Prints a human-readable summary to stdout."""
    print("  DATA EXTRACTION RESULTS")
    print(f"  Extracted at: {results['meta']['extracted_at']}")

    e = results["emails"]
    total_emails = sum(len(v) for v in e.values())
    print(f"\n EMAILS ({total_emails} found)")
    print(f"   ALU Official  : {e['alu_official']}")
    print(f"   ALU Alumni    : {e['alu_alumni']}")
    print(f"   ALU SI        : {e['alu_si']}")
    print(f"   General       : {e['general']}")
    print(f"   Rejected      : {results['rejected']['emails']}")

    print(f"\n URLs ({len(results['urls']['valid'])} valid, {len(results['urls']['flagged'])} flagged)")
    for url in results["urls"]["valid"]:
        print(f"   {url}")
    for item in results["urls"]["flagged"]:
        print(f"  {item['url']}  [{item['reason']}]")

    print(f"\n PHONE NUMBERS ({len(results['phone_numbers'])} found)")
    for p in results["phone_numbers"]:
        print(f"   {p}")

    print(f"\n CREDIT CARDS ({len(results['credit_cards'])} valid, masked)")
    for c in results["credit_cards"]:
        print(f"   {c}")
    print(f"   Rejected (Luhn fail): {len(results['rejected']['cards'])}")

    print(f"\n HTML TAGS ({len(results['html_tags'])} found)")
    for tag in results["html_tags"][:10]:   # Show first 10 to keep output tidy
        print(f"   {tag}")
    if len(results["html_tags"]) > 10:
        print(f"   ... and {len(results['html_tags']) - 10} more")

    print(f"\n  HASHTAGS ({len(results['hashtags'])} found)")
    print(f"   {', '.join(results['hashtags'])}")

    print(f"\n QUARANTINED LINES: {results['quarantined_lines']}")
    print("  Security note:", results["meta"]["security_note"])


def save_json(results: dict, path: Path):
    """Saves the structured results as formatted JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n JSON output saved to: {path}")


if __name__ == "__main__":
    # Resolve paths relative to the project root (one level up from src/)
    project_root = Path(__file__).parent.parent
    input_file   = project_root / "input"  / "raw-text.txt"
    output_file  = project_root / "output" / "sample-output.json"

    if not input_file.exists():
        print(f"ERROR: Input file not found at {input_file}", file=sys.stderr)
        sys.exit(1)

    raw_text = input_file.read_text(encoding="utf-8")

    # Run extraction
    results = extract_all(raw_text)

    # Print summary to console
    print_summary(results)

    # Save JSON output
    save_json(results, output_file)