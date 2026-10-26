import random
import string

def password_generator(length=12, use_symbols=True):
    letters = string.ascii_letters
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

    if use_symbols:
        characters = letters + digits + symbols
    else:
        characters = letters + digits

    password = ''.join(random.choice(characters) for _ in range(length))
    return password