import sys

from textkit.report import build_report, format_line


def main(argv):
    text = " ".join(argv) or "hello world hello"
    print(build_report(text, [1, 2, 3]))
    print(format_line("done", "yes"))


if __name__ == "__main__":
    main(sys.argv[1:])
