"""
====================================================
ScamShield AI
Preprocessing Pipeline
====================================================
"""

from ML.ai_core.normalizer import normalize
from ML.ai_core.tokenizer import tokenize

from ML.ai_core.utils import (
    count_urls,
    count_emails,
    count_phone_numbers,
    count_money,
    count_numbers,
    uppercase_ratio,
    digit_ratio,
    count_special_characters,
    count_repeated_characters,
    average_word_length
)


def preprocess(text):

    original_text = str(text)

    clean_text = normalize(original_text)

    tokens = tokenize(clean_text)

    processed_text = " ".join(tokens)

    result = {

        "original_text": original_text,

        "clean_text": clean_text,

        "processed_text": processed_text,

        "tokens": tokens,

        "statistics": {

            "char_count": len(original_text),

            "word_count": len(tokens),

            "url_count": count_urls(original_text),

            "email_count": count_emails(original_text),

            "phone_count": count_phone_numbers(original_text),

            "money_count": count_money(original_text),

            "number_count": count_numbers(original_text),

            "uppercase_ratio": uppercase_ratio(original_text),

            "digit_ratio": digit_ratio(original_text),

            "special_character_count": count_special_characters(original_text),

            "repeated_character_count": count_repeated_characters(original_text),

            "average_word_length": average_word_length(original_text)

        }

    }

    return result


if __name__ == "__main__":

    sms = input("Enter Message:\n\n")

    result = preprocess(sms)

    print("\n" + "=" * 70)

    print("PREPROCESSING RESULT")

    print("=" * 70)

    print("\nOriginal Text\n")

    print(result["original_text"])

    print("\nNormalized Text\n")

    print(result["clean_text"])

    print("\nProcessed Text\n")

    print(result["processed_text"])

    print("\nTokens\n")

    print(result["tokens"])

    print("\nStatistics\n")

    for key, value in result["statistics"].items():

        print(f"{key:30}: {value}")