from .chatbot_qa import QA_DATA


def normalize_text(text):
    return " ".join(text.lower().strip().split())


def get_answer(user_message):
    message = normalize_text(user_message)

    if not message:
        return (
            "Please enter a question. You can ask me about "
            "phishing, suspicious links, OTPs, SMS scams, or online safety."
        )

    best_match = None
    best_score = 0

    for item in QA_DATA:
        score = 0

        for keyword in item["keywords"]:
            keyword = normalize_text(keyword)

            if keyword in message:
                score += len(keyword.split())

        if score > best_score:
            best_score = score
            best_match = item

    if best_match and best_score > 0:
        return best_match["answer"]

    return (
        "I'm sorry, I don't have a predefined answer for that yet. "
        "You can ask me about phishing, SMS scams, suspicious websites, "
        "OTPs, passwords, or what to do after clicking a suspicious link."
    )