"""Unit tests for the password generator. Run with: python -m unittest

copy_to_clipboard is deliberately untested: it is a best-effort wrapper
around whatever clipboard the host machine offers, and exercising it
would overwrite the real clipboard of whoever runs the tests.
"""
import io
import os
import string
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

import password_generator as pg

ALL_POOLS = [
    string.ascii_uppercase,
    string.ascii_lowercase,
    string.digits,
    string.punctuation,
]


class RemoveAmbiguousTests(unittest.TestCase):
    def test_strips_all_lookalikes(self):
        self.assertEqual(pg.remove_ambiguous("O0Il1"), "")

    def test_keeps_everything_else(self):
        self.assertEqual(pg.remove_ambiguous("abcXYZ29!"), "abcXYZ29!")

    def test_mixed_input(self):
        # O and l are look-alikes; e, r, d, w and the space survive.
        self.assertEqual(pg.remove_ambiguous("HellO wOrld"), "He wrd")


class BuildCharacterPoolsTests(unittest.TestCase):
    def test_all_categories_selected(self):
        pools = pg.build_character_pools(True, True, True, True, False)
        self.assertEqual(pools, ALL_POOLS)

    def test_single_category(self):
        pools = pg.build_character_pools(False, False, True, False, False)
        self.assertEqual(pools, [string.digits])

    def test_no_categories(self):
        pools = pg.build_character_pools(False, False, False, False, False)
        self.assertEqual(pools, [])

    def test_exclude_ambiguous_removes_lookalikes_from_every_pool(self):
        pools = pg.build_character_pools(True, True, True, True, True)
        joined = "".join(pools)
        for lookalike in "O0Il1":
            self.assertNotIn(lookalike, joined)
        # The other characters must still be there.
        self.assertIn("A", joined)
        self.assertIn("2", joined)


class SecureShuffleTests(unittest.TestCase):
    def test_preserves_the_multiset_of_items(self):
        items = list("aabbccddeeff")
        shuffled = items.copy()
        pg.secure_shuffle(shuffled)
        self.assertEqual(sorted(shuffled), sorted(items))

    def test_empty_and_single_item_lists_are_fine(self):
        for items in ([], ["x"]):
            copy = items.copy()
            pg.secure_shuffle(copy)
            self.assertEqual(copy, items)


class GeneratePasswordTests(unittest.TestCase):
    def test_produces_requested_length(self):
        for length in (4, 12, 128):
            self.assertEqual(len(pg.generate_password(length, ALL_POOLS)), length)

    def test_contains_at_least_one_char_from_every_pool(self):
        # Without the per-category guarantee an 8-char password would
        # regularly miss a category, so repeating this catches regressions.
        for _ in range(30):
            password = pg.generate_password(8, ALL_POOLS)
            for pool in ALL_POOLS:
                self.assertTrue(
                    any(ch in pool for ch in password),
                    f"no character from {pool!r} in {password!r}",
                )

    def test_minimum_length_gives_exactly_one_per_category(self):
        password = pg.generate_password(len(ALL_POOLS), ALL_POOLS)
        counts = [sum(ch in pool for ch in password) for pool in ALL_POOLS]
        self.assertEqual(counts, [1, 1, 1, 1])

    def test_only_uses_allowed_characters(self):
        password = pg.generate_password(50, [string.digits])
        self.assertTrue(all(ch in string.digits for ch in password))

    def test_rejects_length_below_category_count(self):
        with self.assertRaises(ValueError):
            pg.generate_password(3, ALL_POOLS)


class EstimateEntropyBitsTests(unittest.TestCase):
    def test_known_value(self):
        # 10 characters from a 64-character pool: 10 * log2(64) = 60 bits.
        self.assertAlmostEqual(pg.estimate_entropy_bits(10, 64), 60.0)

    def test_degenerate_pools_have_zero_entropy(self):
        self.assertEqual(pg.estimate_entropy_bits(10, 1), 0.0)
        self.assertEqual(pg.estimate_entropy_bits(10, 0), 0.0)


class RateStrengthTests(unittest.TestCase):
    def test_short_passwords_are_weak_regardless_of_entropy(self):
        self.assertEqual(pg.rate_strength(7, 4, 200), "Weak")

    def test_single_category_is_weak_regardless_of_length(self):
        self.assertEqual(pg.rate_strength(30, 1, 200), "Weak")

    def test_low_entropy_is_weak(self):
        self.assertEqual(pg.rate_strength(12, 4, 49.9), "Weak")

    def test_two_categories_cap_at_medium(self):
        self.assertEqual(pg.rate_strength(12, 2, 100), "Medium")

    def test_entropy_below_strong_threshold_is_medium(self):
        self.assertEqual(pg.rate_strength(12, 4, 79.9), "Medium")

    def test_strong_needs_length_categories_and_entropy(self):
        self.assertEqual(pg.rate_strength(12, 3, 80), "Strong")
        self.assertEqual(pg.rate_strength(16, 4, 105), "Strong")


class AskYesNoTests(unittest.TestCase):
    def ask(self, answers, default=None):
        with mock.patch("builtins.input", side_effect=answers):
            with redirect_stdout(io.StringIO()):
                return pg.ask_yes_no("? ", default)

    def test_yes_answers(self):
        for answer in ("y", "Y", "yes", " YES "):
            self.assertIs(self.ask([answer]), True)

    def test_no_answers(self):
        for answer in ("n", "N", "no", "No"):
            self.assertIs(self.ask([answer]), False)

    def test_empty_answer_uses_default(self):
        self.assertIs(self.ask([""], default=True), True)
        self.assertIs(self.ask([""], default=False), False)

    def test_empty_answer_without_default_reasks(self):
        self.assertIs(self.ask(["", "y"]), True)

    def test_invalid_answer_reasks(self):
        self.assertIs(self.ask(["banana", "n"]), False)


class AskIntInRangeTests(unittest.TestCase):
    def ask(self, answers, minimum=4, maximum=128):
        with mock.patch("builtins.input", side_effect=answers):
            with redirect_stdout(io.StringIO()):
                return pg.ask_int_in_range("? ", minimum, maximum)

    def test_valid_number(self):
        self.assertEqual(self.ask(["16"]), 16)

    def test_bounds_are_inclusive(self):
        self.assertEqual(self.ask(["4"]), 4)
        self.assertEqual(self.ask(["128"]), 128)

    def test_non_numeric_input_reasks(self):
        self.assertEqual(self.ask(["abc", "", "16"]), 16)

    def test_below_minimum_reasks(self):
        self.assertEqual(self.ask(["3", "-5", "4"]), 4)

    def test_above_maximum_reasks(self):
        self.assertEqual(self.ask(["129", "128"]), 128)


class SavePasswordsTests(unittest.TestCase):
    def test_writes_one_password_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.txt")
            self.assertTrue(pg.save_passwords(["alpha", "beta"], path))
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "alpha\nbeta\n")

    def test_appends_to_an_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.txt")
            pg.save_passwords(["one"], path)
            pg.save_passwords(["two"], path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "one\ntwo\n")

    def test_unwritable_path_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "no_such_dir", "out.txt")
            with redirect_stdout(io.StringIO()):
                self.assertFalse(pg.save_passwords(["x"], path))


if __name__ == "__main__":
    unittest.main()
