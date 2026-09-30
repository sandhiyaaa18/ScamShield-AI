"""
====================================================
ScamShield AI
Entity Detection Engine
====================================================
"""

import json
import os

BASE_DIR = os.path.dirname(__file__)

ENTITY_FILE = os.path.join(
    BASE_DIR,
    "..",
    "knowledge_base",
    "entities.json"
)

with open(ENTITY_FILE, "r", encoding="utf-8") as f:
    ENTITY_DB = json.load(f)


def detect_entities(text):

    text = text.lower()

    found = {}

    total_entities = 0

    for entity_type, keywords in ENTITY_DB.items():

        matches = []

        for keyword in keywords:

            if keyword in text:

                matches.append(keyword)

        found[entity_type] = matches

        total_entities += len(matches)

    return {

        "entity_count": total_entities,

        "entities": found

    }


if __name__ == "__main__":

    sms = input("Enter Message:\n\n")

    result = detect_entities(sms)

    print("\nDetected Entities\n")

    print("=" * 60)

    print()

    print("Total Entities :", result["entity_count"])

    print()

    for entity_type, values in result["entities"].items():

        if values:

            print(f"{entity_type:15}: {values}")