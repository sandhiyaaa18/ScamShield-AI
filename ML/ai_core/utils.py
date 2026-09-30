"""
====================================================
ScamShield AI
Utility Functions
====================================================
"""

import re


def remove_extra_spaces(text):
    """Remove multiple spaces."""
    return re.sub(r"\s+", " ", str(text)).strip()


def count_urls(text):
    """Count URLs."""
    pattern = r"https?://\S+|www\.\S+"
    return len(re.findall(pattern, text, flags=re.IGNORECASE))


def count_emails(text):
    """Count email addresses."""
    pattern = r"\b[\w\.-]+@[\w\.-]+\.\w+\b"
    return len(re.findall(pattern, text))


def count_phone_numbers(text):
    """Count Indian phone numbers."""
    pattern = r"(?:\+91[\-\s]?)?[6-9]\d{9}"
    return len(re.findall(pattern, text))


def count_money(text):
    """Count money values."""
    pattern = r"(₹|\$|rs\.?)\s*\d+"
    return len(re.findall(pattern, text, flags=re.IGNORECASE))


def count_numbers(text):
    """Count standalone numbers."""
    pattern = r"\b\d+\b"
    return len(re.findall(pattern, text))


def uppercase_ratio(text):
    """Ratio of uppercase letters."""
    text = str(text)

    if not text:
        return 0.0

    uppercase = sum(c.isupper() for c in text)

    return round(uppercase / len(text), 4)


def digit_ratio(text):
    """Ratio of digits."""
    text = str(text)

    if not text:
        return 0.0

    digits = sum(c.isdigit() for c in text)

    return round(digits / len(text), 4)


def count_special_characters(text):
    """Count special characters."""
    pattern = r"[!@#$%^&*()_+=<>?/{}[\]|~`]"
    return len(re.findall(pattern, text))


def count_repeated_characters(text):
    """
    Count repeated character sequences.

    Example:
    loooan
    !!!!!!
    """

    pattern = r"(.)\1{2,}"

    return len(re.findall(pattern, text))


def average_word_length(text):
    """Average word length."""

    words = str(text).split()

    if not words:
        return 0

    avg = sum(len(word) for word in words) / len(words)

    return round(avg, 2)


# ==========================================
# Testing
# ==========================================

if __name__ == "__main__":

    sample = """
    URGENT!!

    Visit https://bank-update.xyz

    Contact +91 9876543210

    Pay ₹5000 immediately.

    """

    print("URL Count               :", count_urls(sample))
    print("Email Count             :", count_emails(sample))
    print("Phone Count             :", count_phone_numbers(sample))
    print("Money Count             :", count_money(sample))
    print("Number Count            :", count_numbers(sample))
    print("Uppercase Ratio         :", uppercase_ratio(sample))
    print("Digit Ratio             :", digit_ratio(sample))
    print("Special Character Count :", count_special_characters(sample))
    print("Repeated Characters     :", count_repeated_characters(sample))
    print("Average Word Length     :", average_word_length(sample))