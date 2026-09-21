"""
ANVESH Email Text Cleaner & Normalizer.
Deterministic text normalization for Model 1 (TF-IDF + Logistic Regression).

Guarantees:
- Missing subject/body handling
- Unicode NFKC normalization
- HTML tag stripping with entity unescaping
- Security tokenization (URLs, Emails, Currencies)
- Whitespace normalization
- Deterministic behavior across training, validation, and production inference.
"""

import html
import re
import unicodedata
from typing import Optional, Union

# Regex patterns for security tokenization
URL_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'{}|\\^`]+',
    re.IGNORECASE
)
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)
CURRENCY_PATTERN = re.compile(
    r'[\$£€₹¥]\s*\d+(?:[.,]\d+)*(?:\s*(?:million|billion|thousand|k|m|usd|inr|eur|gbp))?',
    re.IGNORECASE
)
HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
MIME_ARTIFACT_PATTERN = re.compile(r'(?:--=_[A-Za-z0-9._=-]+|Content-Type:[^\n]+|charset=[^\n]+|Content-Transfer-Encoding:[^\n]+)', re.IGNORECASE)
WHITESPACE_PATTERN = re.compile(r'\s+')


def clean_email_text(text: Optional[str]) -> str:
    """
    Clean and normalize raw email text (subject or body).
    
    Args:
        text: Raw text string or None.
        
    Returns:
        Normalized, tokenized text string.
    """
    if text is None or not isinstance(text, str):
        return ""

    # 1. Unicode normalization (NFKC)
    normalized = unicodedata.normalize("NFKC", text)

    # 2. HTML Unescape entities (&amp; -> &, &lt; -> <, etc.)
    normalized = html.unescape(normalized)

    # 3. Strip MIME boundary and header artifacts if leaked into body
    normalized = MIME_ARTIFACT_PATTERN.sub(" ", normalized)

    # 4. Strip HTML tags
    normalized = HTML_TAG_PATTERN.sub(" ", normalized)

    # 5. Tokenize URLs -> __URL_TOKEN__
    normalized = URL_PATTERN.sub(" __URL_TOKEN__ ", normalized)

    # 6. Tokenize Emails -> __EMAIL_TOKEN__
    normalized = EMAIL_PATTERN.sub(" __EMAIL_TOKEN__ ", normalized)

    # 7. Tokenize Currency expressions -> __CURRENCY_TOKEN__
    normalized = CURRENCY_PATTERN.sub(" __CURRENCY_TOKEN__ ", normalized)

    # 8. Normalize whitespace
    normalized = WHITESPACE_PATTERN.sub(" ", normalized).strip()

    return normalized


def normalize_email_pair(subject: Optional[str], body: Optional[str]) -> str:
    """
    Clean and combine subject and body into a single structured text representation.
    
    Args:
        subject: Email subject line.
        body: Email body content.
        
    Returns:
        Combined normalized string for TF-IDF feature extraction.
    """
    clean_subj = clean_email_text(subject)
    clean_bod = clean_email_text(body)

    if clean_subj and clean_bod:
        return f"{clean_subj} {clean_bod}"
    elif clean_subj:
        return clean_subj
    elif clean_bod:
        return clean_bod
    else:
        return "empty_email_content"


class EmailTextPreprocessor:
    """
    Sklearn-compatible or standalone transformer wrapper for email text preprocessing.
    """

    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        """
        X can be a list of tuples (subject, body), dicts, or strings.
        """
        results = []
        for item in X:
            if isinstance(item, tuple) or isinstance(item, list):
                subj = item[0] if len(item) > 0 else ""
                bod = item[1] if len(item) > 1 else ""
                results.append(normalize_email_pair(subj, bod))
            elif isinstance(item, dict):
                subj = item.get("subject", "")
                bod = item.get("body", "")
                results.append(normalize_email_pair(subj, bod))
            elif isinstance(item, str):
                results.append(clean_email_text(item))
            else:
                results.append("empty_email_content")
        return results
