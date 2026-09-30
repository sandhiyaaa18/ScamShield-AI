# scamshield_app/chatbot_qa.py

QA_DATA = [
    {
        "question": "What is phishing?",
        "keywords": [
            "what is phishing",
            "phishing",
            "meaning of phishing",
            "explain phishing",
        ],
        "answer": (
            "Phishing is a scam where attackers pretend to be a trusted "
            "person or organization to trick you into revealing sensitive "
            "information such as passwords, OTPs, banking details, or "
            "card information."
        ),
    },

    {
        "question": "What is smishing?",
        "keywords": [
            "what is smishing",
            "smishing",
            "sms scam",
            "text message scam",
        ],
        "answer": (
            "Smishing is phishing carried out through SMS or text messages. "
            "Scammers may send fake bank alerts, KYC warnings, delivery "
            "messages, prizes, or suspicious links."
        ),
    },

    {
        "question": "What is vishing?",
        "keywords": [
            "what is vishing",
            "vishing",
            "phone call scam",
            "call scam",
        ],
        "answer": (
            "Vishing is a scam performed through phone calls. "
            "Scammers may pretend to be bank employees, government officials, "
            "customer-support agents, or other trusted organizations."
        ),
    },

    {
        "question": "Should I share my OTP?",
        "keywords": [
            "share otp",
            "give otp",
            "tell otp",
            "otp",
            "one time password",
        ],
        "answer": (
            "Never share your OTP with another person. Legitimate banks and "
            "services generally do not require you to disclose your OTP to "
            "someone over a call, SMS, email, or chat."
        ),
    },

    {
        "question": "What should I do if I clicked a phishing link?",
        "keywords": [
            "clicked phishing link",
            "clicked scam link",
            "clicked suspicious link",
            "opened phishing link",
            "clicked a link",
        ],
        "answer": (
            "Stop interacting with the website immediately. Do not enter any "
            "more information. If you entered a password, change it from the "
            "official website or app. If financial information was exposed, "
            "contact your bank or financial institution through an official "
            "channel."
        ),
    },

    {
        "question": "How do I identify a fake website?",
        "keywords": [
            "fake website",
            "identify fake website",
            "detect fake website",
            "website scam",
            "suspicious website",
        ],
        "answer": (
            "Check the domain carefully, look for unusual spelling or "
            "subdomains, avoid unexpected login or payment requests, and "
            "don't rely on HTTPS alone. When in doubt, access the service "
            "through its official app or manually entered official website."
        ),
    },

    {
        "question": "What is a strong password?",
        "keywords": [
            "strong password",
            "secure password",
            "good password",
            "password security",
        ],
        "answer": (
            "Use a long, unique password or passphrase for every important "
            "account. Avoid names, birthdays, phone numbers, and reused "
            "passwords. A password manager can help generate and store "
            "unique passwords."
        ),
    },

    {
        "question": "What should I do if I was scammed?",
        "keywords": [
            "i was scammed",
            "got scammed",
            "scammed",
            "lost money",
            "fraud happened",
        ],
        "answer": (
            "Act quickly. Contact your bank or payment provider through an "
            "official channel if money or financial information is involved. "
            "Secure affected accounts, change compromised passwords, preserve "
            "messages and transaction records, and report the incident to the "
            "appropriate authorities."
        ),
    },

    {
        "question": "What is ScamShield AI?",
        "keywords": [
            "what is scamshield",
            "scamshield ai",
            "about scamshield",
            "how does scamshield work",
        ],
        "answer": (
            "ScamShield AI is a scam-detection platform designed to analyze "
            "potentially suspicious SMS messages, URLs, and emails and "
            "provide a risk assessment and safety guidance."
        ),
    },
]