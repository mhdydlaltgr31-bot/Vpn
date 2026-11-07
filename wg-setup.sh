#!/usr/bin/env bash
# WireGuard server + client config generator (v2)
# اجرا: sudo bash wg-setup.sh
#
# رفع باگ: نسخه قبلی `sysctl --system` را اجرا می‌کرد. روی این VPS کلید
# net.core.default_qdisc وجود ندارد؛ دستور خطا می‌داد و به‌خاطر set -e
# اسکریپت وسط کار متوقف می‌شد. حالا فقط ip_forward تنظیم می‌شود.
set -Eeuo pipefail
trap 'echo "❌ خطا در خط $LINENO: $BASH_COMMAND" >&2' ERR

# ---------- تنظیمات (در صورت نیاز تغییر دهید) ----------
WG_IF="wg0"
WG_PORT="51820"
SERVER_VPN_IP="10.8.0.1"
CLIENT_VPN_IP="10.8.0.2"
VPN_SUBNET_CIDR="24"
CLIENT_NAME="client1"
CLIENT_DNS="1.1.1.1"
WG_DIR="/etc/wireguard"
CLIENT_DIR="/root/wg-clients"
# -------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "این اسکریپت باید با root اجرا شود (sudo)." >&2
    exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
    echo "این اسکریپت فقط روی Debian/Ubuntu کار می‌کند." >&2
    exit 1
fi

APT=(apt-get -y -qq -o DPkg::Lock::Timeout=120)

# آیا کرنل از WireGuard پشتیبانی می‌کند؟
wg_kernel_ok() {
    ip link add wgtest0 type wireguard 2>/dev/null || return 1
    ip link del wgtest0 2>/dev/null || true
}

# تشخیص IP عمومی سرور از چند سرویس
detect_public_ip() {
    local url addr
    for url in https://ifconfig.me https://api.ipify.org https://icanhazip.com; do
        addr=$(curl -4 -fsS --max-time 8 "$url" 2>/dev/null || true)
        addr=${addr//[$'\r\n\t ']/}
        if [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$addr"
            return 0
        fi
    done
    return 1
}

echo "[1/7] نصب بسته‌ها..."
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
"${APT[@]}" update || echo "    هشدار: apt-get update خطا داد؛ ادامه می‌دهیم."
"${APT[@]}" install wireguard-tools iptables iproute2 curl
"${APT[@]}" install qrencode >/dev/null 2>&1 || true

echo "[2/7] بررسی کرنل..."
if ! wg_kernel_ok; then
    modprobe wireguard 2>/dev/null || true
fi
if wg_kernel_ok; then
    echo "    ماژول WireGuard در کرنل موجود است."
else
    echo "    ماژول WireGuard در کرنل نیست؛ نصب wireguard-go (نسخه userspace)..."
    if ! "${APT[@]}" install wireguard-go; then
        echo "❌ کرنل WireGuard ندارد و نصب wireguard-go هم ممکن نشد." >&2
        exit 1
    fi
    if [[ ! -c /dev/net/tun ]]; then
        echo "❌ /dev/net/tun وجود ندارد. گزینه TUN/TAP را در پنل VPS فعال کنید." >&2
        exit 1
    fi
fi
if ! iptables -t nat -L -n >/dev/null 2>&1; then
    echo "❌ NAT (iptables) در این کرنل کار نمی‌کند؛ بدون آن ترافیک اینترنت از VPN عبور نمی‌کند." >&2
    exit 1
fi

echo "[3/7] آماده‌سازی و پشتیبان‌گیری از کانفیگ قبلی (در صورت وجود)..."
mkdir -p "$WG_DIR" "$CLIENT_DIR"
chmod 700 "$WG_DIR" "$CLIENT_DIR"
if [[ -f "$WG_DIR/$WG_IF.conf" ]]; then
    BACKUP_DIR="$WG_DIR/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    for f in "$WG_DIR/$WG_IF.conf" "$WG_DIR"/server_*.key "$WG_DIR/${CLIENT_NAME}"_*.key "$CLIENT_DIR/${CLIENT_NAME}.conf"; do
        if [[ -f "$f" ]]; then
            cp -a "$f" "$BACKUP_DIR/"
        fi
    done
    systemctl stop "wg-quick@${WG_IF}" 2>/dev/null || true
    wg-quick down "$WG_IF" 2>/dev/null || true
    ip link del "$WG_IF" 2>/dev/null || true
    echo "    کانفیگ قبلی پیدا شد؛ پشتیبان: $BACKUP_DIR"
fi

echo "[4/7] تشخیص IP عمومی و اینترفیس خروجی..."
WAN_IF=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
if [[ -z "$WAN_IF" ]]; then
    echo "❌ اینترفیس خروجی (default route) پیدا نشد." >&2
    exit 1
fi
SERVER_PUBLIC_IP=$(detect_public_ip || true)
if [[ -z "$SERVER_PUBLIC_IP" ]]; then
    SERVER_PUBLIC_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)
    echo "    هشدار: IP عمومی از اینترنت تشخیص داده نشد؛ از IP اینترفیس استفاده شد."
fi
if [[ -z "$SERVER_PUBLIC_IP" ]]; then
    echo "❌ IP سرور تشخیص داده نشد." >&2
    exit 1
fi
echo "    IP عمومی: $SERVER_PUBLIC_IP | اینترفیس: $WAN_IF"

echo "[5/7] ساخت کلیدها و کانفیگ‌ها..."
umask 077
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(printf '%s' "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(printf '%s' "$CLIENT_PRIV" | wg pubkey)
printf '%s\n' "$SERVER_PRIV" > "$WG_DIR/server_private.key"
printf '%s\n' "$SERVER_PUB"  > "$WG_DIR/server_public.key"
printf '%s\n' "$CLIENT_PRIV" > "$WG_DIR/${CLIENT_NAME}_private.key"
printf '%s\n' "$CLIENT_PUB"  > "$WG_DIR/${CLIENT_NAME}_public.key"

cat > "$WG_DIR/$WG_IF.conf" <<EOF
[Interface]
Address = ${SERVER_VPN_IP}/${VPN_SUBNET_CIDR}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV}
PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT; iptables -I FORWARD 1 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WAN_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WAN_IF} -j MASQUERADE

[Peer]
# ${CLIENT_NAME}
PublicKey = ${CLIENT_PUB}
AllowedIPs = ${CLIENT_VPN_IP}/32
EOF
chmod 600 "$WG_DIR/$WG_IF.conf"

CLIENT_CONF="$CLIENT_DIR/${CLIENT_NAME}.conf"
cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${CLIENT_VPN_IP}/${VPN_SUBNET_CIDR}
DNS = ${CLIENT_DNS}

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${SERVER_PUBLIC_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
chmod 600 "$CLIENT_CONF"
umask 022

echo "[6/7] فعال‌سازی IP Forwarding..."
# عمداً از `sysctl --system` استفاده نمی‌شود (دلیل در بالای فایل).
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
        echo "❌ فعال‌سازی ip_forward ممکن نشد." >&2
        exit 1
    fi
fi

echo "[7/7] باز کردن پورت و اجرای سرویس..."
UFW_STATUS=$(ufw status 2>/dev/null || true)
if [[ "$UFW_STATUS" == *"Status: active"* ]]; then
    ufw allow "${WG_PORT}/udp" >/dev/null
    echo "    پورت ${WG_PORT}/udp در UFW باز شد."
fi

if [[ -d /run/systemd/system ]]; then
    systemctl enable "wg-quick@${WG_IF}" >/dev/null 2>&1 || true
    if ! systemctl restart "wg-quick@${WG_IF}"; then
        echo "❌ سرویس WireGuard بالا نیامد. آخرین لاگ‌ها:" >&2
        journalctl -u "wg-quick@${WG_IF}" -n 25 --no-pager >&2 || true
        exit 1
    fi
else
    wg-quick up "$WG_IF"
fi

echo
echo "✅ راه‌اندازی با موفقیت انجام شد."
echo "کانفیگ کلاینت: $CLIENT_CONF"
echo "------------------------------------------------"
cat "$CLIENT_CONF"
echo "------------------------------------------------"
if command -v qrencode >/dev/null 2>&1; then
    echo "QR Code (برای اسکن با اپ WireGuard در گوشی):"
    qrencode -t ansiutf8 < "$CLIENT_CONF" || true
fi
echo
echo "وضعیت سرور:"
wg show "$WG_IF" || true
echo
echo "یادآوری: پورت ${WG_PORT}/UDP را در فایروال پنل VPS (Security Group / Firewall ارائه‌دهنده) هم باز کنید."
