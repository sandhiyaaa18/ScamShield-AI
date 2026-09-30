"""
====================================================
ScamShield AI
Character Normalizer
====================================================
"""

import re

# ==========================================
# Character Mapping
# ==========================================

CHAR_MAP = {

    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "1": "t",
    "8": "b",
    "9": "g",

    "@": "a",
    "$": "s",
    "!": "i",
    "|": "l",

    "€": "e",
    "£": "l",
    "¢": "c"
}


def normalize_characters(text):

    text = str(text)

    words = []

    for word in text.split():

        # Check whether the word contains BOTH
        # letters and numbers.
        has_letter = bool(re.search(r"[A-Za-z]", word))
        has_digit = bool(re.search(r"\d", word))

        # Only apply character normalization when
        # numbers are mixed with letters.
        if has_letter and has_digit:

            new_word = ""

            for ch in word:

                new_word += CHAR_MAP.get(ch, ch)

            words.append(new_word)

        else:

            # Standalone numbers remain unchanged.
            # Normal words are also kept unchanged here.
            words.append(word)

    return " ".join(words)


# ==========================================
# Testing
# ==========================================

if __name__ == "__main__":

    sms = input("Enter Message:\n")

    print()

    print(normalize_characters(sms))