"""
====================================================
ScamShield AI
Text Normalizer
====================================================
"""

import json
import re
import unicodedata


from ML.ai_core.char_normalizer import normalize_characters
from ML.ai_core.utils import remove_extra_spaces


# ==========================================
# Obfuscation Dictionary
# ==========================================

import os
import json

BASE_DIR = os.path.dirname(__file__)

OBFUSCATION_FILE = os.path.join(
    BASE_DIR,
    "..",
    "knowledge_base",
    "obfuscation.json"
)

with open(OBFUSCATION_FILE, "r", encoding="utf-8") as f:
    OBFUSCATION_MAP = json.load(f)


# ==========================================
# Unicode Normalization
# ==========================================

def normalize_unicode(text):

    return unicodedata.normalize(

        "NFKC",

        str(text)

    )


# ==========================================
# Replace URLs
# ==========================================

def replace_urls(text):

    return re.sub(

        r"http[s]?://\S+|www\.\S+",

        " URL ",

        text,

        flags=re.IGNORECASE

    )


# ==========================================
# Replace Emails
# ==========================================

def replace_emails(text):

    return re.sub(

        r"\b[\w\.-]+@[\w\.-]+\.\w+\b",

        " EMAIL ",

        text

    )


# ==========================================
# Replace Phones
# ==========================================

def replace_phones(text):

    return re.sub(

        r"(?:\+91[\-\s]?)?[6-9]\d{9}",

        " PHONE ",

        text

    )


# ==========================================
# Replace Money
# ==========================================

def replace_money(text):

    return re.sub(

        r"(₹|\$|rs\.?)\s*\d+",

        " MONEY ",

        text,

        flags=re.IGNORECASE

    )


# ==========================================
# Replace Numbers
# ==========================================

def replace_numbers(text):

    # Only normalize numbers that are part of a word.
    # Standalone numbers such as OTPs, amounts, dates,
    # phone numbers and transaction IDs are preserved.

    def fix_word(match):

        word = match.group(0)

        # Number-to-letter substitutions commonly used
        # in SMS obfuscation.
        replacements = {
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "8": "b"
        }

        for number, letter in replacements.items():
            word = word.replace(number, letter)

        return word

    # Only match alphanumeric words containing BOTH
    # letters and numbers.
    return re.sub(
        r"\b(?=\w*[A-Za-z])(?=\w*\d)\w+\b",
        fix_word,
        text
    )


# ==========================================
# Normalize Obfuscated Words
# ==========================================

def normalize_obfuscation(text):

    for wrong, correct in OBFUSCATION_MAP.items():
        pattern = r"\b" + re.escape(wrong) + r"\b"

        text = re.sub(
            pattern,
            correct,
            text,
            flags=re.IGNORECASE
        )

    return text


# ==========================================
# Remove Extra Symbols
# ==========================================

def remove_noise(text):

    text = re.sub(

        r"[^\w\s]",

        " ",

        text

    )

    return remove_extra_spaces(text)


# ==========================================
# Complete Normalization
# ==========================================

def normalize(text):

    text = normalize_unicode(text)

    text = text.lower()

    text = normalize_characters(text)

    text = normalize_obfuscation(text)

    text = replace_urls(text)

    text = replace_emails(text)

    text = replace_phones(text)

    text = replace_money(text)

    text = replace_numbers(text)

    text = remove_noise(text)

    return text


# ==========================================
# Testing
# ==========================================

if __name__ == "__main__":

    sms = input("Enter Message:\n\n")

    print()

    print("=" * 60)

    print("NORMALIZED TEXT")

    print("=" * 60)

    print()

    print(normalize(sms))