# regex_hackathon
This is a hackathon to put into practice my knowledge on data extraction and secure validation using regex.
# ALU Regex Data Extraction & Secure Validation

A Python program that extracts and validates structured data from raw, production-style text using regex patterns, with security-first handling of hostile or malformed input.

---

## Project Structure

'''
alu-regex-data-extraction/
input/
  raw-text.txt          # Realistic messy input (support tickets, CRM data, API dumps)
src/
  main.py               # Extraction + validation logic
output/
 sample-output.json    # Pre-generated sample output
README.md
'''

---

## How to Run

**Requirements:** Python 3.8+, no external dependencies.

'''bash
# From the project root:
python3 src/main.py
'''

Results are printed to the console and saved to 'output/sample-output.json'.

---

## Data Types Extracted

1 **Email addresses** Standard + plus-addressing; classified into ALU categories
2 **URLs** http/https/ftp; flagged for path traversal or non-HTTP schemes 
3 **Phone numbers** East African, US, and local Kenyan formats
4 **Credit card numbers** | Visa, MasterCard; Luhn-validated; **always masked in output**
5 **HTML tags** Opening, closing, self-closing; '<script>' blocked |
6 **Hashtags**Social-media style '#tag' extraction

### ALU Email Validation

Emails are classified into three ALU-specific categories:

ALU Official  '@alueducation.com'
ALU Alumni '@alumni.alueducation.com'
ALU SI (Student Innovator) '@si.alueducation.com'

Each is validated with a dedicated pattern that enforces a properly-formed local part (no leading/trailing dots, no double-dots, must start with an alphanumeric character).

---

## Security Design

The program applies a **"never trust input"** model:

### 1. Hostile-Pattern Quarantine
Before any regex extraction runs on a line, it is scanned for:
- **SQL injection** fragments ('OR 1=1', 'DROP TABLE', etc.)
- **XSS** attempts ('<script>')
- **Null bytes** or hex escapes ('\x00')
- **Path traversal** sequences ('../', '..\')
- **IP-literal emails** ('admin@[127.0.0.1]')

Lines matching any hostile pattern are **quarantined** — skipped entirely, with a count reported.

### 2. Credit Card Masking
Full card numbers are **never stored or logged**. Immediately after a card number is extracted and validated, it is replaced with '****-****-****-XXXX' (showing only the last 4 digits). The raw number exists only briefly in memory during the Luhn check.

### 3. Luhn Algorithm Validation
All extracted card numbers pass the [Luhn checksum](https://en.wikipedia.org/wiki/Luhn_algorithm) before being accepted. This rejects:
- Fabricated numbers ('9999 9999 9999 9999')
- All-zero numbers ('0000 0000 0000 0000')
- Randomly typed digit sequences

### 4. Secondary Email Validation
The regex catch is not the final word. Extracted emails are also checked for:
- Consecutive dots ('..')
- Local part starting or ending with a dot
- Double '@@'

### 5. URL Safety Check
URLs are checked for path-traversal sequences ('../', '%2e%2e') even after the hostile-line check, and are flagged rather than silently accepted.

### 6. Phone Number Sanity Check
After extraction, phone numbers are checked to ensure they are not all-zero sequences and meet a minimum digit count.

---

## Sample Output (abbreviated)

'''json
{
  "emails": {
    "alu_official": ["lead@alueducation.com", "p.osei@alueducation.com"],
    "alu_alumni":   ["d.kamau@alumni.alueducation.com"],
    "alu_si":       ["amina.hassan@si.alueducation.com"],
    "general":      ["james.mwangi@techsolutions.co.ke", "..."]
  },
  "credit_cards": ["****-****-****-1111", "****-****-****-9903"],
  "quarantined_lines": 6
}
'''

Full output is in 'output/sample-output.json'.