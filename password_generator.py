"""Command-line password generator built on the secrets module."""

import math
import secrets
import string

AMBIGUOUS_CHARACTERS = set("O0Il1")

MEDIUM_ENTROPY_BITS = 50
STRONG_ENTROPY_BITS = 80

MIN_LENGTH = 4
MAX_LENGTH = 128
MAX_BATCH_SIZE = 50


def ask_yes_no(prompt, default=None):
    """Empty input selects ``default`` when one is given."""
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


def remove_ambiguous(characters):
    return "".join(c for c in characters if c not in AMBIGUOUS_CHARACTERS)


def build_character_pools(use_uppercase, use_lowercase, use_digits,
                          use_symbols, exclude_ambiguous):
    """One pool per selected category. They stay separate so the generator
    can guarantee a character from each.
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


def secure_shuffle(items):
    """Fisher-Yates driven by secrets.randbelow. random.shuffle is
    predictable and must not be used here.
    """
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(length, pools):
    """Takes one character from every pool, fills the rest from all of them
    combined, then shuffles so the guaranteed ones are not always in front.
    """
    if length < len(pools):
        raise ValueError("Length must be at least the number of categories.")

    password_chars = [secrets.choice(pool) for pool in pools]

    all_characters = "".join(pools)
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(all_characters) for _ in range(remaining)]

    secure_shuffle(password_chars)
    return "".join(password_chars)


def estimate_entropy_bits(length, pool_size):
    """length * log2(pool_size). The one-per-category guarantee makes the
    true value slightly lower, so this is an upper bound.
    """
    if pool_size <= 1:
        return 0.0
    return length * math.log2(pool_size)


def rate_strength(length, category_count, entropy_bits):
    if length < 8 or category_count == 1 or entropy_bits < MEDIUM_ENTROPY_BITS:
        return "Weak"
    if category_count < 3 or entropy_bits < STRONG_ENTROPY_BITS:
        return "Medium"
    return "Strong"


def copy_to_clipboard(text):
    """Returns False instead of raising when no clipboard is available."""
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


def get_generation_options():
    """Returns ``(pools, length, count)``."""
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

    # Long enough to fit one character from every selected category.
    min_length = max(MIN_LENGTH, len(pools))
    length = ask_int_in_range(
        f"Password length ({min_length}-{MAX_LENGTH}): ",
        min_length, MAX_LENGTH)

    count = ask_int_in_range(
        f"How many passwords? (1-{MAX_BATCH_SIZE}): ", 1, MAX_BATCH_SIZE)

    return pools, length, count


def show_results(passwords, length, pools):
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


def main():
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
        print("\nCancelled. Goodbye!")
