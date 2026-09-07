# Secure Password Generator

[![CI](https://github.com/ItsMrZxD/password-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/ItsMrZxD/password-generator/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A cryptographically secure command-line password generator in Python, built
on the `secrets` module — with entropy estimation, strength rating, batch
generation, and clipboard support. Standard library only.**

Random password generation done correctly: this uses Python's
[`secrets`](https://docs.python.org/3/library/secrets.html) module, which draws
from the operating system's cryptographically secure random source, rather than
`random`, whose Mersenne Twister output is predictable from observed values and
must never be used for passwords or tokens.

You choose the length and which character categories to include, and the
generator guarantees at least one character from every category you selected.
It can skip ambiguous look-alikes, rate the result, estimate its entropy in
bits, generate a batch at once, copy to the clipboard, and append the results
to a text file.

## Features

- **Cryptographically secure** — `secrets.choice` and `secrets.randbelow`
  throughout, never `random`
- **Category guarantee** — at least one character from each selected category
  (uppercase, lowercase, digits, symbols)
- **Ambiguous-character exclusion** — optionally drop `O`, `0`, `I`, `l`, `1`
  for passwords that have to be read aloud or typed from a screen
- **Entropy estimation** in bits, with a Weak / Medium / Strong rating
- **Batch generation** — up to 50 passwords at once
- **Clipboard copy** with graceful fallback, and **append-to-file** export
- Configurable length from 4 to 128 characters
- No third-party packages required

## Requirements

Python 3.9 or newer, standard library only — there is nothing to install.

Clipboard copying will use [`pyperclip`](https://pypi.org/project/pyperclip/)
if it happens to be installed, and otherwise falls back to `tkinter` from the
standard library. If neither is available the generator says so and carries on,
so clipboard support is entirely optional.

## Installation

```bash
git clone https://github.com/ItsMrZxD/password-generator
cd password-generator
python password_generator.py
```

## Usage

```bash
python password_generator.py
```

The tool is **interactive and takes no command-line flags** — it prompts for
everything in sequence:

| Prompt | Default | Accepted values |
|---|---|---|
| Include uppercase letters? | Yes | `y` / `n` |
| Include lowercase letters? | Yes | `y` / `n` |
| Include numbers? | Yes | `y` / `n` |
| Include symbols? | Yes | `y` / `n` |
| Exclude ambiguous characters (`O`, `0`, `I`, `l`, `1`)? | No | `y` / `n` |
| Password length | — | 4–128 (never below the number of selected categories) |
| How many passwords? | — | 1–50 |
| Copy the first password to the clipboard? | No | `y` / `n` |
| Save the password(s) to a text file? | No | `y` / `n` |
| Generate another password? | No | `y` / `n` |

At least one character category must be selected; the tool re-asks if you
decline all four. Invalid and out-of-range input is rejected and re-prompted
rather than crashing.

### Example session

```
============================================================
          SECURE PASSWORD GENERATOR
============================================================
Include uppercase letters? (Y/n): y
Include lowercase letters? (Y/n): y
Include numbers? (Y/n): y
Include symbols? (Y/n): y
Exclude ambiguous characters (O, 0, I, l, 1)? (y/N): n
Password length (4-128): 16
How many passwords? (1-50): 1

------------------------------------------------------------
Your password:  @aC&!#*QvBEg]7|1
------------------------------------------------------------
Strength: Strong   |   Entropy: ~104.9 bits   |   Pool size: 94 characters
```

### Scripted use

The prompts read from standard input, so a session can be piped. This generates
one 16-character password from all four categories and exits:

```bash
printf 'y\ny\ny\ny\nn\n16\n1\nn\nn\nn\n' | python password_generator.py
```

## How it works

**Generation.** One character is drawn from each selected category pool first,
which is what guarantees the category mix. The remaining positions are filled
from the combined pool, and the result is shuffled so the guaranteed characters
do not always land at the front.

**Shuffling.** The shuffle is a Fisher–Yates pass driven by
`secrets.randbelow`. `random.shuffle` is deliberately not used — seeding it from
observable output would make the arrangement predictable.

**Entropy.** Reported as `length × log2(pool_size)`. Note that this is an
**upper bound**: the one-per-category guarantee slightly constrains the space,
so true entropy is a little lower. For a 16-character password over all 94
printable ASCII characters that gives ~104.9 bits.

**Strength rating** combines all three signals:

| Rating | Condition |
|---|---|
| Weak | length < 8, or only one category selected, or entropy < 50 bits |
| Medium | fewer than 3 categories, or entropy < 80 bits |
| Strong | 3+ categories and entropy ≥ 80 bits |

## Tests

```bash
python -m unittest
```

35 tests covering pool construction, the category guarantee, ambiguous-character
removal, entropy maths, strength thresholds, and the file-save path. CI runs
them against Python 3.9 and 3.14 on every push.

## Limitations and security notes

- **The save option writes plain text.** That is fine for testing, but do not
  use it to store real passwords — use a password manager. The tool prints a
  reminder when you save.
- **Entropy is an upper bound**, not an exact measure, for the reason described
  above.
- **Only the first password is copied** to the clipboard when generating a
  batch.
- **Clipboard contents are not cleared** afterwards, and may persist or sync to
  other devices depending on your OS.
- Saving **appends** to the target file rather than overwriting it, so repeated
  runs accumulate.
- The strength rating is a heuristic based on length, category count, and
  entropy. It does not check against breached-password lists or dictionary
  words.
- Symbols come from `string.punctuation`; some systems and websites reject
  particular symbols from that set.

## License

MIT — see [LICENSE](LICENSE).
