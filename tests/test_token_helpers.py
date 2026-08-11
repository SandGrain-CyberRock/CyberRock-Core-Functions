"""Verify the extracted helpers behave identically to the inline originals.

These two helpers were lifted out of the 27 demo scripts during the
2026-08-10 restructure. The point of these tests is not that the helpers
work in isolation, but that they are faithful copies -- so the originals
are reproduced here and compared against.
"""
import hashlib
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import CyberRock_Token as token


def original_strToList(numberstring):
    """The idiom duplicated verbatim across all 27 original scripts."""
    return [int(numberstring[i:i + 2], 16) for i in range(0, len(numberstring), 2)]


def original_make_challenge():
    """The timestamp-challenge idiom duplicated across 18 original scripts."""
    curr = time.time()
    curr_time = time.strftime("%a %d %b %Y %H %M %S", time.gmtime(curr))
    hash_func = hashlib.new('sha256')
    hash_func.update(str(curr_time).encode('utf-8'))
    return hash_func.hexdigest()


class TestHexToBytes(unittest.TestCase):
    def test_matches_original_on_a_tid(self):
        tid = "0123456789abcdef" * 4
        self.assertEqual(token.hex_to_bytes(tid), original_strToList(tid))

    def test_matches_original_on_a_challenge(self):
        cw = "ff00" * 32
        self.assertEqual(token.hex_to_bytes(cw), original_strToList(cw))

    def test_produces_32_bytes_for_a_64_char_challenge(self):
        self.assertEqual(len(token.hex_to_bytes("ab" * 32)), 32)

    def test_empty_string_yields_empty_list(self):
        self.assertEqual(token.hex_to_bytes(""), [])


class TestMakeChallenge(unittest.TestCase):
    def test_matches_original_within_the_same_second(self):
        # Both idioms hash a 1-second-granularity timestamp, so calls in the
        # same second must agree. Retry once to survive a second boundary.
        for _ in range(2):
            mine, theirs = token.make_challenge(), original_make_challenge()
            if mine == theirs:
                break
        self.assertEqual(mine, theirs)

    def test_returns_64_hex_chars(self):
        challenge = token.make_challenge()
        self.assertEqual(len(challenge), 64)
        int(challenge, 16)  # raises ValueError if not hex

    def test_round_trips_through_hex_to_bytes_to_32_bytes(self):
        self.assertEqual(len(token.hex_to_bytes(token.make_challenge())), 32)


if __name__ == "__main__":
    unittest.main()
