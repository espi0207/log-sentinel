"""Avisos por Telegram, Discord o un webhook cualquiera.

Solo usa urllib. Las credenciales salen de variables de entorno y no de argumentos,
para que no queden en el historial del shell ni se vean en `ps`:

    Telegram:  TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID
    Discord:   DISCORD_WEBHOOK_URL
    Webhook:   LOGSENTINEL_WEBHOOK_URL  (le llega el hallazgo en JSON)

TODO: si llegan muchos avisos de golpe habría que agruparlos en uno. Telegram no deja
mandar más de unos 20 mensajes por minuto a un mismo grupo.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from .ansi import clean
from .detectors import Finding, Severity

ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🔵"}


class NotifyError(Exception):
    pass


def format_message(finding: Finding, host: str = "") -> str:
    lines = [
        f"{ICON[finding.severity]} [{finding.severity.label}] log-sentinel" + (f" en {host}" if host else ""),
        clean(finding.title),
        clean(finding.details),
    ]
    if finding.mitre:
        lines.append(f"MITRE ATT&CK: {finding.mitre}")
    lines.append(f"{finding.first_seen:%Y-%m-%d %H:%M:%S} -> {finding.last_seen:%H:%M:%S}")
    return "\n".join(lines)


def _post(url: str, payload: dict, opener: Callable, timeout: float) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener(request, timeout=timeout) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        raise NotifyError(f"el servidor respondió {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        # Ojo con meter la URL en el mensaje: en Discord la propia URL es la contraseña.
        raise NotifyError(f"no se pudo conectar ({exc.reason})") from exc
    except (OSError, ValueError) as exc:
        raise NotifyError(f"no se pudo enviar ({type(exc).__name__})") from exc


@dataclass
class TelegramNotifier:
    token: str
    chat_id: str
    name: str = "Telegram"

    def send(self, finding: Finding, host: str = "", opener: Callable = urllib.request.urlopen, timeout=10) -> None:
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        _post(url, {"chat_id": self.chat_id, "text": format_message(finding, host)}, opener, timeout)


@dataclass
class DiscordNotifier:
    url: str
    name: str = "Discord"

    def send(self, finding: Finding, host: str = "", opener: Callable = urllib.request.urlopen, timeout=10) -> None:
        _post(self.url, {"content": format_message(finding, host)}, opener, timeout)


@dataclass
class WebhookNotifier:
    url: str
    name: str = "webhook"

    def send(self, finding: Finding, host: str = "", opener: Callable = urllib.request.urlopen, timeout=10) -> None:
        payload = {"text": format_message(finding, host), "finding": finding.to_dict(), "host": host}
        _post(self.url, payload, opener, timeout)


def _check_url(url: str, variable: str, allow_http: bool = False) -> str:
    parts = urlsplit(url)
    schemes = ("https", "http") if allow_http else ("https",)
    if parts.scheme not in schemes or not parts.netloc:
        # No se imprime la URL por si es un secreto (un webhook de Discord lo es).
        raise NotifyError(f"{variable} no es una URL válida: tiene que empezar por {schemes[0]}://")
    return url


def build_notifier(kind: str, env: dict[str, str] | None = None):
    """Crea el notificador con las credenciales del entorno. Lanza NotifyError si falta algo."""
    env = os.environ if env is None else env
    if kind == "telegram":
        token, chat = env.get("TELEGRAM_BOT_TOKEN"), env.get("TELEGRAM_CHAT_ID")
        if not token or not chat:
            raise NotifyError("faltan TELEGRAM_BOT_TOKEN y/o TELEGRAM_CHAT_ID en el entorno")
        if "/" in token:
            raise NotifyError("TELEGRAM_BOT_TOKEN no tiene el formato de un token de @BotFather")
        return TelegramNotifier(token, chat)
    if kind == "discord":
        url = env.get("DISCORD_WEBHOOK_URL")
        if not url:
            raise NotifyError("falta DISCORD_WEBHOOK_URL en el entorno")
        return DiscordNotifier(_check_url(url, "DISCORD_WEBHOOK_URL"))
    if kind == "webhook":
        url = env.get("LOGSENTINEL_WEBHOOK_URL")
        if not url:
            raise NotifyError("falta LOGSENTINEL_WEBHOOK_URL en el entorno")
        return WebhookNotifier(_check_url(url, "LOGSENTINEL_WEBHOOK_URL", allow_http=True))
    raise NotifyError(f"notificador desconocido: {kind}")
