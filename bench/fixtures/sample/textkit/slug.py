import re


def slugify(text, max_length=40):
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    if len(text) > max_length:
        text = text[:max_length].rstrip("-")
    return text


def is_slug(text):
    return bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", text))
