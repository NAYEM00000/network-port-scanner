import unittest
from src.scanner import parse_ports


class TestPortParser(unittest.TestCase):
    def test_single_and_multiple_ports(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("20-22"), [20, 21, 22])

    def test_mixed_input(self):
        self.assertEqual(parse_ports("22,80-82"), [22, 80, 81, 82])

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-1")


if __name__ == "__main__":
    unittest.main()
