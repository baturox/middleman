import unittest

from textkit.report import build_report


class ReportTests(unittest.TestCase):
    def test_report_has_word_count(self):
        out = build_report("a b a", [1, 3])
        self.assertIn("words", out)
        self.assertIn("3", out)


if __name__ == "__main__":
    unittest.main()
