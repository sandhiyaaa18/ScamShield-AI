"""
====================================================
ScamShield AI
Tokenizer
====================================================
"""

import re

import nltk

from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

STOPWORDS = set(stopwords.words("english"))

IMPORTANT_WORDS = {

    "otp",
    "upi",
    "bank",
    "account",
    "credit",
    "debit",
    "card",
    "loan",
    "kyc",
    "aadhaar",
    "pan",
    "verify",
    "verification",
    "payment",
    "pay",
    "transaction",
    "refund",
    "cashback",
    "reward",
    "rewarded",
    "lottery",
    "winner",
    "won",
    "claim",
    "click",
    "link",
    "login",
    "password",
    "security",
    "secure",
    "update",
    "urgent",
    "immediately",
    "blocked",
    "suspended",
    "limited",
    "expire",
    "expired",
    "delivery",
    "parcel",
    "courier",
    "amazon",
    "flipkart",
    "paytm",
    "phonepe",
    "gpay",
    "googlepay",
    "wallet",
    "netbanking",
    "banking",
    "crypto",
    "investment",
    "profit",
    "bonus",
    "offer",
    "free",
    "gift",
    "voucher",
    "coupon",
    "prize"

}

STOPWORDS = STOPWORDS - IMPORTANT_WORDS


def tokenize(text):

    text = text.lower()

    tokens = word_tokenize(text)

    cleaned = []

    for token in tokens:

        token = token.strip()

        if len(token) < 2:
            continue

        # Keep letters and numbers
        token = re.sub(r"[^a-z0-9]", "", token)

        if token == "":
            continue

        if token in STOPWORDS:
            continue

        cleaned.append(token)

    return cleaned


if __name__ == "__main__":

    sms = input("Message : ")

    print()

    print(tokenize(sms))