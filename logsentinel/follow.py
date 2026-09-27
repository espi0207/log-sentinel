"""Seguir un log en vivo como `tail -F`, sin perderse cuando logrotate lo rota.

logrotate renombra auth.log a auth.log.1 y crea un auth.log nuevo. Un tail hecho a
mano se quedaría leyendo el viejo para siempre. Aquí se comprueba en cada lectura si
el fichero de la ruta sigue siendo el mismo (mismo inode y no ha encogido) y, si no,
se termina de leer el viejo y se abre el nuevo desde el principio.
"""

from __future__ import annotations

import os
from pathlib import Path

# Una línea de log no mide tanto. Si algo escribe sin saltos de línea, no quiero que
# el buffer crezca sin límite.
MAX_LINE = 64 * 1024


class Tailer:
    def __init__(self, path: Path | str, from_start: bool = False) -> None:
        self.path = Path(path)
        self._fh = None
        self._inode: int | None = None
        self._pending = b""
        self._from_start = from_start

    def _open(self) -> bool:
        try:
            fh = open(self.path, "rb")
        except OSError:
            # Si el log aún no existe, lo que se escriba cuando aparezca es todo nuevo.
            self._from_start = True
            return False
        if not self._from_start:
            fh.seek(0, os.SEEK_END)  # al arrancar, solo interesa lo que llegue a partir de ahora
        self._fh = fh
        self._inode = os.fstat(fh.fileno()).st_ino
        self._from_start = True  # si hay que reabrir (rotación), el nuevo se lee entero
        return True

    def _rotated(self) -> bool:
        try:
            disk = self.path.stat()
        except OSError:
            return False  # justo entre el renombrado y la creación del nuevo: se reintenta luego
        return disk.st_ino != self._inode or disk.st_size < self._fh.tell()

    def read_new(self) -> list[str]:
        """Devuelve las líneas completas que han aparecido desde la última llamada."""
        if self._fh is None and not self._open():
            return []
        data = self._fh.read()
        if self._rotated():
            # Lo que se escribió en el fichero viejo justo antes de rotar ya está en `data`.
            self._fh.close()
            self._fh = None
            self._pending += data
            if self._pending and not self._pending.endswith(b"\n"):
                self._pending += b"\n"  # el resto de esa línea ya no va a llegar
            data = self._fh.read() if self._open() else b""

        self._pending += data
        *lines, self._pending = self._pending.split(b"\n")
        if len(self._pending) > MAX_LINE:
            lines.append(self._pending)
            self._pending = b""
        # Se decodifica línea a línea: si se decodificara el bloque entero, un carácter
        # UTF-8 partido entre dos lecturas acabaría convertido en basura.
        return [line.decode("utf-8", errors="replace").rstrip("\r") for line in lines]

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
