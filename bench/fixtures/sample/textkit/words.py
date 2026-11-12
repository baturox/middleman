import re


def split_words(text):
    return re.findall(r"[A-Za-z']+", text)


def word_count(text):
    return len(split_words(text))


def top_words(text, n=3):
    counts = {}
    for w in split_words(text):
        w = w.lower()
        counts[w] = counts.get(w, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[:n]


def capitalize_words(text):
    return " ".join(w.capitalize() for w in text.split())
