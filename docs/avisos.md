# Avisos por Telegram o Discord

Con `--follow`, log-sentinel se queda vigilando el log y puede mandarte un mensaje
cuando detecta algo. Por defecto solo avisa de lo que tenga prioridad alta o
crítica; con `--min-severity medium` (o `low`) avisa de más cosas.

Las credenciales se pasan con variables de entorno y no como argumentos, para que
no se queden en el historial del shell ni se vean con `ps`.

## Telegram

1. Habla con [@BotFather](https://t.me/BotFather) en Telegram, mándale `/newbot` y
   sigue los pasos. Al final te da un token del estilo
   `123456789:AAExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`.
2. Escríbele cualquier cosa a tu bot nuevo, si no, no puede mandarte mensajes.
3. Para saber tu chat id, abre en el navegador
   `https://api.telegram.org/bot<TOKEN>/getUpdates` y busca `"chat":{"id":...`.
4. Arranca con las dos variables:

```bash
export TELEGRAM_BOT_TOKEN="123456789:AAE..."
export TELEGRAM_CHAT_ID="123456789"
logsentinel /var/log/auth.log --follow --notify telegram
```

## Discord

En el servidor de Discord: ajustes del canal, Integraciones, Webhooks, Nuevo
webhook, y copias la URL. Esa URL es como una contraseña: quien la tenga puede
escribir en el canal.

```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
logsentinel /var/log/auth.log --follow --notify discord
```

## Webhook genérico

Para mandarlo a cualquier otra cosa (un script tuyo, n8n, un SIEM...). Hace un
POST con este JSON:

```json
{
  "text": "🔴 [CRÍTICA] log-sentinel en srv-web01\nAcceso correcto de 'backup' desde 203.0.113.99 tras 8 fallos\n...",
  "finding": {
    "severity": "CRÍTICA",
    "rule": "success_after_failures",
    "title": "Acceso correcto de 'backup' desde 203.0.113.99 tras 8 fallos",
    "ip": "203.0.113.99",
    "user": "backup",
    "count": 8,
    "first_seen": "2026-09-25T15:41:14",
    "last_seen": "2026-09-25T15:42:29",
    "mitre": "T1078 Valid Accounts",
    "details": "método: password. Posible credencial adivinada: ..."
  },
  "host": "srv-web01"
}
```

```bash
export LOGSENTINEL_WEBHOOK_URL="https://mi-servicio.example/hook"
logsentinel /var/log/auth.log --follow --notify webhook
```

Se pueden usar varios canales a la vez: `--notify telegram --notify discord`.

## Comprobar que llegan

Lo más fácil es inventarse un log con un acceso como root (prioridad media) y
leerlo desde el principio:

```bash
LC_ALL=C date '+%b %e %H:%M:%S prueba sshd[1]: Accepted password for root from 192.0.2.1 port 22 ssh2' > /tmp/prueba.log
logsentinel /tmp/prueba.log --follow --from-start --notify telegram --min-severity medium
```

Debería llegarte un mensaje al momento. Se sale con Ctrl-C.

## Dejarlo funcionando con systemd

Instálalo en `/opt` en vez de en tu carpeta personal, para que el servicio pueda
leerlo:

```bash
sudo git clone https://github.com/espi0207/log-sentinel.git /opt/log-sentinel
sudo python3 -m venv /opt/log-sentinel/.venv
sudo /opt/log-sentinel/.venv/bin/pip install /opt/log-sentinel
```

Las credenciales van en un fichero aparte que solo puede leer root
(`/etc/log-sentinel.env`, con permisos 600):

```bash
sudo install -m 600 /dev/null /etc/log-sentinel.env
sudoedit /etc/log-sentinel.env
```

```ini
TELEGRAM_BOT_TOKEN=123456789:AAE...
TELEGRAM_CHAT_ID=123456789
```

Y el servicio, en `/etc/systemd/system/log-sentinel.service`:

```ini
[Unit]
Description=log-sentinel, vigilancia de auth.log
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/log-sentinel/.venv/bin/logsentinel /var/log/auth.log --follow --notify telegram --host %H
EnvironmentFile=/etc/log-sentinel.env
# Sin esto Python guarda la salida en un buffer y journalctl no la enseña hasta mucho después
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=5

# No hace falta ser root: en Debian y Ubuntu los logs son legibles por el grupo adm.
DynamicUser=yes
SupplementaryGroups=adm
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now log-sentinel
journalctl -u log-sentinel -f
```

systemd lee el `EnvironmentFile` antes de cambiar de usuario, por eso puede ser
solo de root. En RHEL/Fedora el log es `/var/log/secure` y solo lo puede leer root,
así que ahí hay que quitar `DynamicUser` y `SupplementaryGroups`.

Para un log de nginx es lo mismo añadiendo `--web` y cambiando la ruta
(`/var/log/nginx/access.log`, que en Debian también es del grupo adm).
