"""
====================================================
ScamShield AI
Rule Engine
====================================================
"""

import json
import os

BASE_DIR = os.path.dirname(__file__)

RULE_FILE = os.path.join(
    BASE_DIR,
    "..",
    "knowledge_base",
    "scam_rules.json"
)

with open(RULE_FILE, "r", encoding="utf-8") as f:
    RULES = json.load(f)


def evaluate_rules(text):

    text = text.lower()

    total_score = 0

    matched_rules = []

    matched_keywords = []

    for rule_name, rule in RULES.items():

        score = rule["weight"]

        keywords = rule["keywords"]

        found = []

        for keyword in keywords:

            if keyword.lower() in text:

                found.append(keyword)

        if found:

            total_score += score

            matched_rules.append(rule_name)

            matched_keywords.extend(found)

    return {

        "rule_score": total_score,

        "matched_rules": matched_rules,

        "matched_keywords": matched_keywords

    }


if __name__ == "__main__":

    sms = input("Enter Message:\n\n")

    result = evaluate_rules(sms)

    print("\n" + "=" * 60)

    print("RULE ENGINE RESULT")

    print("=" * 60)

    print()

    print("Rule Score :", result["rule_score"])

    print()

    print("Matched Rules")

    for rule in result["matched_rules"]:
        print("✓", rule)

    print()

    print("Matched Keywords")

    for word in result["matched_keywords"]:
        print("-", word)