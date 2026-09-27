"""Colores para la terminal sin depender de colorama ni rich.

Si la salida no es una terminal (por ejemplo `> informe.txt`) o existe NO_COLOR
(https://no-color.org) no se pinta nada. FORCE_COLOR obliga a pintar.
"""

from __future__ import annotations

import os
import sys

CODES = {
    "bold": "1",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "cyan": "36",
    "gray": "90",
    "bright_red": "91",
}

if os.name == "nt":
    os.system("")  # truco conocido: activa las secuencias ANSI en la consola de Windows


def enabled(stream=None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def paint(text: str, *styles: str, stream=None) -> str:
    if not styles or not enabled(stream):
        return text
    return f"\033[{';'.join(CODES[s] for s in styles)}m{text}\033[0m"


def clean(text: str) -> str:
    """Escapa los caracteres no imprimibles de un texto que sale del log.

    Los nombres de usuario de SSH y las URLs los escribe el atacante. Si se
    imprimen tal cual, puede colar secuencias ANSI que borran líneas de la
    terminal o le cambian el título. Con esto se ven como \\x1b en vez de
    ejecutarse.
    """
    if text.isprintable():
        return text
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in text)
