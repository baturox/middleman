import unittest

from textkit.words import top_words, word_count


class WordsTests(unittest.TestCase):
    def test_word_count(self):
        self.assertEqual(word_count("one two  three"), 3)

    def test_top_words(self):
        self.assertEqual(top_words("a b a c a b", 2), [("a", 3), ("b", 2)])


if __name__ == "__main__":
    unittest.main()
