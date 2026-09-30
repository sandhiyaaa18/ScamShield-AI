"""
ScamShield AI
Email Parser

Reads .eml files and extracts:
- Sender
- Recipient
- Subject
- Plain text
- HTML content
- URLs
- Attachments
"""

import os
import re
from email import policy
from email.parser import BytesParser


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    """
    Extract URLs from email text.
    """

    if not text:
        return []

    pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"

    urls = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    return list(dict.fromkeys(urls))


# ============================================================
# EMAIL BODY EXTRACTION
# ============================================================

def extract_body(message):
    """
    Extract plain text and HTML body from an email.
    """

    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()
            disposition = str(
                part.get("Content-Disposition", "")
            ).lower()

            # Ignore attachments
            if "attachment" in disposition:
                continue

            try:

                content = part.get_content()

            except Exception:

                continue

            if content_type == "text/plain":

                plain_text += "\n" + str(content)

            elif content_type == "text/html":

                html_text += "\n" + str(content)

    else:

        try:

            content = message.get_content()

        except Exception:

            content = ""

        if message.get_content_type() == "text/html":

            html_text = str(content)

        else:

            plain_text = str(content)

    return (
        plain_text.strip(),
        html_text.strip()
    )


# ============================================================
# ATTACHMENT EXTRACTION
# ============================================================

def extract_attachments(message):
    """
    Extract attachment names and basic information.
    """

    attachments = []

    if not message.is_multipart():
        return attachments

    for part in message.walk():

        disposition = str(
            part.get("Content-Disposition", "")
        ).lower()

        if "attachment" not in disposition:
            continue

        filename = part.get_filename()

        if filename:

            payload = part.get_payload(
                decode=True
            )

            size = (
                len(payload)
                if payload
                else 0
            )

            attachments.append(
                {
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size": size
                }
            )

    return attachments


# ============================================================
# HEADER EXTRACTION
# ============================================================

def extract_headers(message):
    """
    Extract important email headers.
    """

    headers = {}

    important_headers = [
        "From",
        "To",
        "Cc",
        "Reply-To",
        "Return-Path",
        "Subject",
        "Date",
        "Message-ID",
        "Received",
        "Authentication-Results"
    ]

    for header in important_headers:

        values = message.get_all(
            header,
            []
        )

        if values:

            headers[header] = values

    return headers


# ============================================================
# PARSE EMAIL
# ============================================================

def parse_email(file_path):
    """
    Parse an .eml file and return structured email data.
    """

    if not os.path.exists(file_path):

        raise FileNotFoundError(
            f"Email file not found: {file_path}"
        )

    with open(
        file_path,
        "rb"
    ) as file:

        message = BytesParser(
            policy=policy.default
        ).parse(file)

    # --------------------------------------------------------
    # Basic information
    # --------------------------------------------------------

    sender = message.get(
        "From",
        ""
    )

    recipient = message.get(
        "To",
        ""
    )

    subject = message.get(
        "Subject",
        ""
    )

    date = message.get(
        "Date",
        ""
    )

    reply_to = message.get(
        "Reply-To",
        ""
    )

    # --------------------------------------------------------
    # Body
    # --------------------------------------------------------

    plain_text, html_text = extract_body(
        message
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = extract_urls(
        plain_text + "\n" + html_text
    )

    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    attachments = extract_attachments(
        message
    )

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    headers = extract_headers(
        message
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {

        "sender": sender,

        "recipient": recipient,

        "reply_to": reply_to,

        "subject": subject,

        "date": date,

        "plain_text": plain_text,

        "html": html_text,

        "urls": urls,

        "attachments": attachments,

        "headers": headers

    }


# ============================================================
# COMMAND LINE TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("SCAMSHIELD AI - EMAIL PARSER")
    print("=" * 70)
    print()

    file_path = input(
        "Enter .eml file path:\n\n"
    ).strip()

    try:

        result = parse_email(file_path)

        # ====================================================
        # BASIC INFORMATION
        # ====================================================

        print()
        print("=" * 70)
        print("EMAIL INFORMATION")
        print("=" * 70)

        print()

        print("Sender      :", result["sender"])
        print("Recipient   :", result["recipient"])
        print("Reply-To    :", result["reply_to"])
        print("Subject     :", result["subject"])
        print("Date        :", result["date"])

        # ====================================================
        # EMAIL BODY
        # ====================================================

        print()
        print("-" * 70)
        print("EMAIL BODY")
        print("-" * 70)

        body = result["plain_text"].strip()

        if body:

            # Don't dump extremely long emails
            max_length = 3000

            if len(body) > max_length:

                print(
                    body[:max_length]
                )

                print()
                print(
                    "... [EMAIL BODY TRUNCATED]"
                )

            else:

                print(body)

        else:

            print(
                "No plain-text body available."
            )

        # ====================================================
        # HTML
        # ====================================================

        print()
        print("-" * 70)
        print("HTML EMAIL")
        print("-" * 70)

        if result["html"]:

            print(
                "HTML Available : YES"
            )

            print(
                "HTML Size      :",
                len(result["html"]),
                "characters"
            )

        else:

            print(
                "HTML Available : NO"
            )

        # ====================================================
        # URLS
        # ====================================================

        print()
        print("-" * 70)
        print(
            f"LINKS FOUND : {len(result['urls'])}"
        )
        print("-" * 70)

        if result["urls"]:

            for index, url in enumerate(
                result["urls"],
                start=1
            ):

                print(
                    f"{index}. {url}"
                )

        else:

            print(
                "No URLs found."
            )

        # ====================================================
        # ATTACHMENTS
        # ====================================================

        print()
        print("-" * 70)
        print(
            f"ATTACHMENTS : {len(result['attachments'])}"
        )
        print("-" * 70)

        if result["attachments"]:

            for attachment in result[
                "attachments"
            ]:

                print(
                    f"Name : {attachment['filename']}"
                )

                print(
                    f"Type : {attachment['content_type']}"
                )

                print(
                    f"Size : {attachment['size']} bytes"
                )

                print()

        else:

            print(
                "No attachments found."
            )

        # ====================================================
        # IMPORTANT HEADERS
        # ====================================================

        print()
        print("-" * 70)
        print("IMPORTANT EMAIL HEADERS")
        print("-" * 70)

        headers = result["headers"]

        for name in [
            "Return-Path",
            "Reply-To",
            "Authentication-Results"
        ]:

            values = headers.get(
                name,
                []
            )

            if values:

                print(
                    f"{name}:"
                )

                for value in values:

                    print(
                        f"  {value}"
                    )

        # ====================================================
        # COMPLETED
        # ====================================================

        print()
        print("=" * 70)
        print("EMAIL PARSING COMPLETED")
        print("=" * 70)
        print()

    except Exception as error:

        print()
        print("=" * 70)
        print("ERROR")
        print("=" * 70)
        print()

        print(error)