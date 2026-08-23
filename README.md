# Password Generator

[![CI](https://github.com/ItsMrZxD/password-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/ItsMrZxD/password-generator/actions/workflows/ci.yml)

> **Note:** This is my 4th project — I finished it a while ago and completely
> forgot to upload it to GitHub. Better late than never!

A secure command-line password generator written in Python. It uses the
`secrets` module (not `random`) so the generated passwords are
cryptographically secure.

You pick the length and which character types to include, and it guarantees at
least one character from every category you selected. It can also skip
ambiguous look-alikes (`O`, `0`, `I`, `l`, `1`), rate the result and estimate
its entropy, generate a batch at once, copy to the clipboard, and append the
passwords to a text file.

## Requirements

Python 3.x — standard library only, nothing to install.

## Usage

```
python password_generator.py
```

Then just answer the prompts. Example:

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
Your password:  kbHJ^YY4>AL:(.m\
------------------------------------------------------------
Strength: Strong   |   Entropy: ~105.4 bits   |   Pool size: 94 characters
```

## Tests

```
python -m unittest
```

## A note on saving passwords

The save option writes passwords to a **plain text file**. That's fine for
testing, but don't use it to store real passwords — use a proper password
manager for that.

## License

MIT — see [LICENSE](LICENSE).
