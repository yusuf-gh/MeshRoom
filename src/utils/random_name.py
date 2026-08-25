import struct
import random
from names_generator import generate_name

def generate_anonymous_nickname() -> str:

    base_name = generate_name(style='underscore')

    # случайное число в конец, чтобы снизить риск совпадения ников в одной комнате)
    suffix = random.randint(10, 99)

    return f"{base_name}_{suffix}"