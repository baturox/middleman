from textkit.stats import mean
from textkit.words import top_words, word_count


def format_line(label, value):
    return f"{label:<12}{value}"


def build_report(text, numbers):
    lines = [
        format_line("words", word_count(text)),
        format_line("mean", round(mean(numbers), 2)),
    ]
    for word, count in top_words(text, 2):
        lines.append(format_line(word, count))
    return "\n".join(lines)
