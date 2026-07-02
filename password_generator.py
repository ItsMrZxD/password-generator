"""
Secure Password Generator
=========================

A command-line application that generates cryptographically secure
passwords using Python's ``secrets`` module.

Features
--------
* Choose the password length and which character categories to include
  (uppercase, lowercase, digits, symbols).
* Guarantees at least one character from every selected category.
* Optionally excludes ambiguous look-alike characters (O, 0, I, l, 1).
* Rates the password strength (Weak / Medium / Strong) and shows an
  estimate of the password entropy in bits.
* Can generate several passwords at once, copy the result to the
  clipboard (when possible) and save passwords to a text file.

Only the Python standard library is required.
"""

import math
import secrets
import string

# Characters that are easily confused with one another in many fonts.
AMBIGUOUS_CHARACTERS = set("O0Il1")

# Entropy thresholds (in bits) used by the strength rating.
MEDIUM_ENTROPY_BITS = 50
STRONG_ENTROPY_BITS = 80

# Sensible limits so a typo cannot request a gigantic password or batch.
MIN_LENGTH = 4
MAX_LENGTH = 128
MAX_BATCH_SIZE = 50


# --------------------------------------------------------------------------
# Input helpers
# --------------------------------------------------------------------------

def ask_yes_no(prompt, default=None):
    """Ask a yes/no question and return the answer as a boolean.

    Keeps asking until the user types a valid answer.  If ``default``
    is given (True or False), pressing Enter on an empty line selects
    that default.
    """
    while True:
        answer = input(prompt).strip().lower()
        if answer == "" and default is not None:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


def ask_int_in_range(prompt, minimum, maximum):
    """Ask for a whole number between ``minimum`` and ``maximum``.

    Rejects non-numeric input, negative numbers and values outside the
    allowed range, and keeps asking until the input is valid.
    """
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
        except ValueError:
            print("Please enter a whole number.")
            continue
        if value < minimum:
            print(f"Please enter a number of at least {minimum}.")
        elif value > maximum:
            print(f"Please enter a number no larger than {maximum}.")
        else:
            return value


# --------------------------------------------------------------------------
# Character pools
# --------------------------------------------------------------------------

def remove_ambiguous(characters):
    """Return ``characters`` with ambiguous look-alikes removed."""
    return "".join(c for c in characters if c not in AMBIGUOUS_CHARACTERS)


def build_character_pools(use_uppercase, use_lowercase, use_digits,
                          use_symbols, exclude_ambiguous):
    """Build one pool of characters per selected category.

    Returns a list of strings, one per selected category.  Keeping the
    categories separate (instead of one big string) lets the generator
    guarantee at least one character from each of them.
    """
    pools = []
    if use_uppercase:
        pools.append(string.ascii_uppercase)
    if use_lowercase:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(string.punctuation)
    if exclude_ambiguous:
        pools = [remove_ambiguous(pool) for pool in pools]
    return pools


# --------------------------------------------------------------------------
# Password generation
# --------------------------------------------------------------------------

def secure_shuffle(items):
    """Shuffle a list in place using cryptographically secure randomness.

    This is the Fisher-Yates shuffle driven by ``secrets.randbelow``.
    ``random.shuffle`` must not be used here because the ``random``
    module is predictable and unsafe for secrets.
    """
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(length, pools):
    """Generate one password of ``length`` characters.

    Picks one guaranteed character from every pool first, fills the
    rest of the password from all pools combined, then shuffles so the
    guaranteed characters do not always sit at the start.
    """
    if length < len(pools):
        raise ValueError("Length must be at least the number of categories.")

    # One guaranteed character per selected category.
    password_chars = [secrets.choice(pool) for pool in pools]

    # Fill the remaining positions from every allowed character.
    all_characters = "".join(pools)
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(all_characters) for _ in range(remaining)]

    secure_shuffle(password_chars)
    return "".join(password_chars)


# --------------------------------------------------------------------------
# Strength and entropy
# --------------------------------------------------------------------------

def estimate_entropy_bits(length, pool_size):
    """Estimate password entropy in bits.

    Entropy = length * log2(pool_size): each character adds
    log2(pool_size) bits because it is drawn uniformly from the pool.
    The "one per category" guarantee makes the true value slightly
    lower, so this is a close upper bound.
    """
    if pool_size <= 1:
        return 0.0
    return length * math.log2(pool_size)


def rate_strength(length, category_count, entropy_bits):
    """Rate a password as 'Weak', 'Medium' or 'Strong'.

    The rating combines length, character diversity (how many
    categories are in use) and the entropy estimate.
    """
    if length < 8 or category_count == 1 or entropy_bits < MEDIUM_ENTROPY_BITS:
        return "Weak"
    if category_count < 3 or entropy_bits < STRONG_ENTROPY_BITS:
        return "Medium"
    return "Strong"


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def copy_to_clipboard(text):
    """Try to copy ``text`` to the clipboard; return True on success.

    Prefers the third-party ``pyperclip`` library if it happens to be
    installed, then falls back to the standard-library ``tkinter``.
    Never raises: if no clipboard mechanism works, it simply returns
    False and the program carries on.
    """
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass

    try:
        import tkinter
        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()  # hand the text over to the system clipboard
        root.destroy()
        return True
    except Exception:
        return False


def save_passwords(passwords, filename):
    """Append the passwords to a text file; return True on success."""
    try:
        with open(filename, "a", encoding="utf-8") as file:
            for password in passwords:
                file.write(password + "\n")
        return True
    except OSError as error:
        print(f"Could not save the file: {error}")
        return False


# --------------------------------------------------------------------------
# User interaction
# --------------------------------------------------------------------------

def get_generation_options():
    """Ask the user for all generation settings.

    Returns a tuple ``(pools, length, count)``.  Re-asks the category
    questions until at least one category is selected.
    """
    while True:
        use_uppercase = ask_yes_no("Include uppercase letters? (Y/n): ", True)
        use_lowercase = ask_yes_no("Include lowercase letters? (Y/n): ", True)
        use_digits = ask_yes_no("Include numbers? (Y/n): ", True)
        use_symbols = ask_yes_no("Include symbols? (Y/n): ", True)
        if any((use_uppercase, use_lowercase, use_digits, use_symbols)):
            break
        print("\nYou must select at least one character category.\n")

    exclude_ambiguous = ask_yes_no(
        "Exclude ambiguous characters (O, 0, I, l, 1)? (y/N): ", False)

    pools = build_character_pools(use_uppercase, use_lowercase, use_digits,
                                  use_symbols, exclude_ambiguous)

    # The password must be long enough to fit one character from every
    # selected category.
    min_length = max(MIN_LENGTH, len(pools))
    length = ask_int_in_range(
        f"Password length ({min_length}-{MAX_LENGTH}): ",
        min_length, MAX_LENGTH)

    count = ask_int_in_range(
        f"How many passwords? (1-{MAX_BATCH_SIZE}): ", 1, MAX_BATCH_SIZE)

    return pools, length, count


def show_results(passwords, length, pools):
    """Print the generated passwords with strength and entropy info."""
    pool_size = sum(len(pool) for pool in pools)
    entropy_bits = estimate_entropy_bits(length, pool_size)
    strength = rate_strength(length, len(pools), entropy_bits)

    print("\n" + "-" * 60)
    if len(passwords) == 1:
        print(f"Your password:  {passwords[0]}")
    else:
        print("Your passwords:")
        for number, password in enumerate(passwords, start=1):
            print(f"  {number:>3}: {password}")
    print("-" * 60)
    print(f"Strength: {strength}   |   "
          f"Entropy: ~{entropy_bits:.1f} bits   |   "
          f"Pool size: {pool_size} characters\n")


def offer_extras(passwords):
    """Offer to copy the (first) password and/or save them to a file."""
    if ask_yes_no("Copy the first password to the clipboard? (y/N): ", False):
        if copy_to_clipboard(passwords[0]):
            print("Copied to clipboard.")
        else:
            print("No clipboard support available - skipping.")

    if ask_yes_no("Save the password(s) to a text file? (y/N): ", False):
        filename = input("File name [passwords.txt]: ").strip()
        if not filename:
            filename = "passwords.txt"
        if save_passwords(passwords, filename):
            print(f"Saved to {filename}. "
                  "Remember: the file is plain text - keep it safe!")


# --------------------------------------------------------------------------
# Main program
# --------------------------------------------------------------------------

def main():
    """Run the interactive password generator loop."""
    print("=" * 60)
    print("          SECURE PASSWORD GENERATOR")
    print("=" * 60)

    while True:
        pools, length, count = get_generation_options()
        passwords = [generate_password(length, pools) for _ in range(count)]
        show_results(passwords, length, pools)
        offer_extras(passwords)

        if not ask_yes_no("\nGenerate another password? (y/N): ", False):
            print("Goodbye - stay secure!")
            break
        print()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        # Exit cleanly on Ctrl+C instead of showing a traceback.
        print("\nCancelled. Goodbye!")
