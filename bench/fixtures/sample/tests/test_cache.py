import unittest

from textkit.cache import Cache


class CacheTests(unittest.TestCase):
    def test_evicts_oldest(self):
        c = Cache(2)
        c.put("a", 1)
        c.put("b", 2)
        c.get("a")
        c.put("c", 3)
        self.assertIsNone(c.get("b"))
        self.assertEqual(c.get("a"), 1)


if __name__ == "__main__":
    unittest.main()
