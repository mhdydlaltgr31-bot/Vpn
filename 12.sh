#!/bin/bash
# WireGuard server + client config generator (نسخه ۳)
#
# قابلیت‌ها:
#  - رفع باگ sysctl (دیگر sysctl --system اجرا نمی‌شود)
#  - چند پورت UDP همزمان + یک کانفیگ جدا برای هر پورت (اگر پورتی فیلتر بود، بعدی را امتحان کنید)
#  - MTU کوچک‌تر و TCP MSS clamp (جلوگیری از «وصل است ولی سایت‌ها باز نمی‌شوند»)
#  - لینک دانلود HTTPS (ساب) با توکن تصادفی که بعد از مدتی خودش خاموش می‌شود
#
# اجرا:           sudo bash wg-setup.sh
# تغییر تنظیمات:   sudo WG_PORT=443 SUB_TTL_HOURS=2 bash wg-setup.sh
set -eEuo pipefail

# ---------- تنظیمات (با متغیر محیطی هم قابل تغییرند) ----------
WG_IF="${WG_IF:-wg0}"
WG_PORT="${WG_PORT:-51820}"              # پورت اصلی UDP
ALT_PORTS="${ALT_PORTS-443 53 4500}"     # پورت‌های UDP اضافه (با فاصله)؛ ALT_PORTS="" = غیرفعال
SERVER_VPN_IP="${SERVER_VPN_IP:-10.8.0.1}"
CLIENT_VPN_IP="${CLIENT_VPN_IP:-10.8.0.2}"
VPN_SUBNET_CIDR="${VPN_SUBNET_CIDR:-24}"
CLIENT_NAME="${CLIENT_NAME:-client1}"
CLIENT_DNS="${CLIENT_DNS:-1.1.1.1}"
WG_MTU="${WG_MTU:-1280}"                 # اگر سرعت کم بود 1380 یا 1420 را امتحان کنید
SUB_ENABLE="${SUB_ENABLE:-1}"            # 1 = ساخت لینک دانلود، 0 = غیرفعال
SUB_PORT="${SUB_PORT:-}"                 # پورت TCP لینک؛ خالی = خودکار (443 و ...)
SUB_TTL_HOURS="${SUB_TTL_HOURS:-24}"     # بعد از این مدت لینک خاموش می‌شود؛ 0 = نامحدود
WG_DIR="/etc/wireguard"
CLIENT_DIR="/root/wg-clients"
SUB_DIR="/opt/wg-sub"
# ---------------------------------------------------------------

STAGE="main"
UFW_ACTIVE=0

on_err() {
    echo "❌ خطا در خط $1: $2" >&2
    if [[ "$STAGE" == "sub" ]]; then
        echo "   WireGuard سالم و آماده است؛ فقط ساخت لینک دانلود ناموفق بود (کانفیگ‌ها: ${CLIENT_DIR})." >&2
    fi
}
trap 'on_err "$LINENO" "$BASH_COMMAND"' ERR

die() { echo "❌ $*" >&2; exit 1; }
sub_fail() {
    echo "❌ $*" >&2
    echo "   WireGuard سالم و آماده است؛ فقط ساخت لینک دانلود ناموفق بود (کانفیگ‌ها: ${CLIENT_DIR})." >&2
    exit 1
}
is_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 )); }

[[ $EUID -eq 0 ]] || die "این اسکریپت باید با root اجرا شود (sudo)."
command -v apt-get >/dev/null 2>&1 || die "این اسکریپت فقط برای اوبونتو/دبیان است (apt-get پیدا نشد)."
[[ "$WG_IF" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || die "WG_IF نامعتبر است."
[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9_-]+$ ]] || die "CLIENT_NAME فقط می‌تواند شامل حروف انگلیسی، عدد، - و _ باشد."
is_port "$WG_PORT" || die "WG_PORT نامعتبر است."
[[ -z "$SUB_PORT" ]] || is_port "$SUB_PORT" || die "SUB_PORT نامعتبر است."
[[ "$SUB_TTL_HOURS" =~ ^[0-9]+$ ]] || die "SUB_TTL_HOURS باید عدد باشد."
[[ "$WG_MTU" =~ ^1[0-9]{3}$ ]] && (( WG_MTU >= 1280 && WG_MTU <= 1500 )) || die "WG_MTU باید بین 1280 و 1500 باشد."

# ساخت یک فایل کانفیگ کلاینت: write_client_conf <مسیر فایل> <پورت>
write_client_conf() {
    local file="$1" port="$2"
    cat > "$file" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${CLIENT_VPN_IP}/${VPN_SUBNET_CIDR}
DNS = ${CLIENT_DNS}
MTU = ${WG_MTU}

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${SERVER_PUBLIC_IP}:${port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    chmod 600 "$file"
}

# ساخت لینک دانلود HTTPS (ساب)
setup_sub() {
    local p entry tcp_listen ok ttl_line

    tcp_listen=$(ss -ltn 2>/dev/null | awk 'NR>1{print $(NF-1)}' || true)
    if [[ -n "$SUB_PORT" ]]; then
        if grep -Eq ":${SUB_PORT}$" <<<"$tcp_listen"; then
            sub_fail "پورت TCP ${SUB_PORT} اشغال است؛ SUB_PORT دیگری بدهید."
        fi
        SUB_PORT_USE="$SUB_PORT"
    else
        SUB_PORT_USE=""
        for p in 443 8443 2053 2083 2087 2096; do
            if ! grep -Eq ":${p}$" <<<"$tcp_listen"; then
                SUB_PORT_USE="$p"
                break
            fi
        done
        if [[ -z "$SUB_PORT_USE" ]]; then
            SUB_PORT_USE=$((20000 + RANDOM % 30000))
        fi
    fi

    if ! id wgsub >/dev/null 2>&1; then
        useradd --system --user-group --no-create-home --shell /usr/sbin/nologin wgsub
    fi

    SUB_TOKEN=$(openssl rand -hex 16)
    mkdir -p "$SUB_DIR/www/$SUB_TOKEN"

    # گواهی self-signed برای IP سرور
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout "$SUB_DIR/key.pem" -out "$SUB_DIR/cert.pem" \
        -subj "/CN=${SERVER_PUBLIC_IP}" -addext "subjectAltName=IP:${SERVER_PUBLIC_IP}" >/dev/null 2>&1

    # سرور HTTPS حداقلی: فقط محتوای پوشه www را سرو می‌کند، لیست پوشه ندارد، لاگ نمی‌گیرد
    cat > "$SUB_DIR/server.py" <<'PYEOF'
#!/usr/bin/env python3
import functools
import http.server
import os
import socketserver
import ssl
import sys
import urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "www")
PORT = int(sys.argv[1])


class Handler(http.server.SimpleHTTPRequestHandler):
    timeout = 15
    server_version = "wg-sub"
    sys_version = ""
    _status = 0

    def handle(self):
        try:
            self.request.do_handshake()
        except Exception:
            return
        super().handle()

    def send_response(self, code, message=None):
        self._status = code
        super().send_response(code, message)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        name = os.path.basename(urllib.parse.unquote(urllib.parse.urlsplit(self.path).path))
        if self._status == 200 and name.endswith(".conf"):
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % name)
        super().end_headers()

    def list_directory(self, path):
        self.send_error(404)
        return None

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


httpd = Server(("0.0.0.0", PORT), functools.partial(Handler, directory=ROOT))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(os.path.join(BASE, "cert.pem"), os.path.join(BASE, "key.pem"))
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
httpd.serve_forever()
PYEOF

    # کانفیگ‌ها + صفحه‌ی فهرست
    for entry in "${CLIENT_FILES[@]}"; do
        cp "$CLIENT_DIR/${entry%%:*}" "$SUB_DIR/www/$SUB_TOKEN/"
    done
    {
        cat <<'HTML'
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireGuard</title>
<style>
:root{color-scheme:light dark}
body{font-family:system-ui,sans-serif;max-width:30rem;margin:1.5rem auto;padding:0 1rem;line-height:1.8}
a{display:block;padding:.9rem 1rem;margin:.5rem 0;border:1px solid #888;border-radius:.6rem;text-decoration:none;direction:ltr;text-align:left}
</style>
</head>
<body>
<h2>کانفیگ WireGuard</h2>
<p>یک فایل را دانلود کنید و در اپ WireGuard با «Import from file» اضافه کنید. اگر وصل نشد، فایل بعدی (با پورت دیگر) را امتحان کنید.</p>
HTML
        for entry in "${CLIENT_FILES[@]}"; do
            echo "<a href=\"${entry%%:*}\" download>${entry%%:*} &nbsp;(UDP ${entry##*:})</a>"
        done
        echo "</body></html>"
    } > "$SUB_DIR/www/$SUB_TOKEN/index.html"

    # دسترسی‌ها: سرویس با کاربر بدون امتیاز wgsub اجرا می‌شود
    chown -R root:wgsub "$SUB_DIR"
    chmod 750 "$SUB_DIR" "$SUB_DIR/www" "$SUB_DIR/www/$SUB_TOKEN"
    chmod 644 "$SUB_DIR/server.py" "$SUB_DIR/cert.pem"
    chmod 640 "$SUB_DIR/key.pem" "$SUB_DIR/www/$SUB_TOKEN"/*

    ttl_line=""
    if [[ "$SUB_TTL_HOURS" != "0" ]]; then
        ttl_line="RuntimeMaxSec=${SUB_TTL_HOURS}h"
    fi
    cat > /etc/systemd/system/wg-sub.service <<EOF
[Unit]
Description=WireGuard config download page
After=network-online.target

[Service]
User=wgsub
Group=wgsub
ExecStart=$(command -v python3) ${SUB_DIR}/server.py ${SUB_PORT_USE}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
${ttl_line}

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 /etc/systemd/system/wg-sub.service
    systemctl daemon-reload
    if [[ "$SUB_TTL_HOURS" == "0" ]]; then
        systemctl enable --now wg-sub >/dev/null 2>&1
    else
        systemctl restart wg-sub
    fi

    if [[ "$UFW_ACTIVE" == "1" ]]; then
        ufw allow "${SUB_PORT_USE}/tcp" >/dev/null
    fi

    ok=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if (exec 3<>"/dev/tcp/127.0.0.1/${SUB_PORT_USE}") 2>/dev/null; then
            ok=1
            break
        fi
        sleep 0.5
    done
    if [[ "$ok" != "1" ]]; then
        journalctl -u wg-sub --no-pager -n 15 >&2 || true
        sub_fail "سرویس wg-sub بالا نیامد (آخرین لاگ‌ها بالا چاپ شد)."
    fi

    SUB_BASE="https://${SERVER_PUBLIC_IP}:${SUB_PORT_USE}/${SUB_TOKEN}"
    {
        echo "صفحه همه‌ی کانفیگ‌ها: ${SUB_BASE}/"
        for entry in "${CLIENT_FILES[@]}"; do
            echo "${entry%%:*}: ${SUB_BASE}/${entry%%:*}"
        done
    } > "$CLIENT_DIR/sub-link.txt"
    chmod 600 "$CLIENT_DIR/sub-link.txt"
}

echo "[1/8] نصب بسته‌ها و بررسی پشتیبانی کرنل..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
PKGS=(wireguard iptables curl iproute2 openssl)
if [[ "$SUB_ENABLE" == "1" ]]; then
    PKGS+=(python3)
fi
apt-get install -y -o DPkg::Lock::Timeout=120 "${PKGS[@]}"
apt-get install -y qrencode >/dev/null 2>&1 || true

modprobe wireguard 2>/dev/null || true
if ip link add wgtest0 type wireguard 2>/dev/null; then
    ip link del wgtest0
else
    die "کرنل این VPS از WireGuard پشتیبانی نمی‌کند (kernel: $(uname -r)). روی OpenVZ/LXC معمولاً کار نمی‌کند؛ VPS با KVM یا کرنل جدیدتر بخواهید."
fi

echo "[2/8] تشخیص IP عمومی، اینترفیس و پورت‌ها..."
ROUTE_INFO=$(ip -4 route get 1.1.1.1)
WAN_IF=$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$ROUTE_INFO")
LOCAL_IP=$(awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$ROUTE_INFO")
SERVER_PUBLIC_IP=$(curl -4 -fsS --max-time 10 https://ifconfig.me 2>/dev/null \
    || curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
if ! [[ "$SERVER_PUBLIC_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    SERVER_PUBLIC_IP="$LOCAL_IP"
fi
[[ -n "$WAN_IF" && -n "$SERVER_PUBLIC_IP" ]] || die "تشخیص اینترفیس یا IP عمومی ناموفق بود."
echo "    IP عمومی: $SERVER_PUBLIC_IP | اینترفیس: $WAN_IF"

# پورت‌های UDP اضافه: نامعتبر، تکراری و پورت‌هایی که سرویس دیگری روی آن‌ها گوش می‌دهد حذف می‌شوند
UDP_LISTEN=$(ss -lun 2>/dev/null | awk 'NR>1{print $(NF-1)}' || true)
ALT_LIST=()
for p in $ALT_PORTS; do
    if ! is_port "$p"; then
        echo "    ⚠️ پورت نامعتبر نادیده گرفته شد: $p"
        continue
    fi
    if [[ "$p" == "$WG_PORT" ]] || [[ " ${ALT_LIST[*]-} " == *" $p "* ]]; then
        continue
    fi
    if grep -Eq "^(0\.0\.0\.0|\*|\[::\]|${LOCAL_IP//./\\.}):${p}$" <<<"$UDP_LISTEN"; then
        echo "    ⚠️ پورت UDP ${p} توسط سرویس دیگری استفاده می‌شود؛ رد شد."
        continue
    fi
    ALT_LIST+=("$p")
done
UDP_PORTS="$WG_PORT"
for p in "${ALT_LIST[@]+"${ALT_LIST[@]}"}"; do
    UDP_PORTS+=" $p"
done
echo "    پورت‌های UDP: $UDP_PORTS"

echo "[3/8] ساخت کلیدها..."
mkdir -p "$WG_DIR" "$CLIENT_DIR"
chmod 700 "$WG_DIR" "$CLIENT_DIR"
umask 077

# اگر از اجرای قبلی (کامل یا نیمه‌کاره) چیزی مانده: سرویس‌ها را خاموش و فایل‌ها را بکاپ بگیر
systemctl stop wg-sub 2>/dev/null || true
rm -rf "$SUB_DIR/www"
rm -f "$CLIENT_DIR/sub-link.txt"
if systemctl is-active --quiet "wg-quick@${WG_IF}" 2>/dev/null; then
    systemctl stop "wg-quick@${WG_IF}"
fi
if ip link show "$WG_IF" >/dev/null 2>&1; then
    wg-quick down "$WG_IF" >/dev/null 2>&1 || ip link del "$WG_IF" 2>/dev/null || true
fi
BACKUP_DIR="$WG_DIR/backup-$(date +%Y%m%d-%H%M%S)"
for f in "$WG_IF.conf" server_private.key server_public.key \
         "${CLIENT_NAME}_private.key" "${CLIENT_NAME}_public.key"; do
    if [[ -f "$WG_DIR/$f" ]]; then
        mkdir -p "$BACKUP_DIR"
        mv "$WG_DIR/$f" "$BACKUP_DIR/$f"
    fi
done
shopt -s nullglob
for f in "$CLIENT_DIR/${CLIENT_NAME}.conf" "$CLIENT_DIR/${CLIENT_NAME}"-p*.conf; do
    if [[ -f "$f" ]]; then
        mkdir -p "$BACKUP_DIR"
        mv "$f" "$BACKUP_DIR/client-$(basename "$f")"
    fi
done
shopt -u nullglob
if [[ -d "$BACKUP_DIR" ]]; then
    echo "    فایل‌های قبلی در $BACKUP_DIR بکاپ شدند."
fi

SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
printf '%s\n' "$SERVER_PRIV" > "$WG_DIR/server_private.key"
printf '%s\n' "$SERVER_PUB"  > "$WG_DIR/server_public.key"
printf '%s\n' "$CLIENT_PRIV" > "$WG_DIR/${CLIENT_NAME}_private.key"
printf '%s\n' "$CLIENT_PUB"  > "$WG_DIR/${CLIENT_NAME}_public.key"

echo "[4/8] ساخت کانفیگ سرور..."
UP=("iptables -I FORWARD 1 -i %i -j ACCEPT"
    "iptables -I FORWARD 1 -o %i -j ACCEPT"
    "iptables -t nat -A POSTROUTING -o ${WAN_IF} -j MASQUERADE"
    "iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true")
DOWN=("iptables -D FORWARD -i %i -j ACCEPT || true"
      "iptables -D FORWARD -o %i -j ACCEPT || true"
      "iptables -t nat -D POSTROUTING -o ${WAN_IF} -j MASQUERADE || true"
      "iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true")
for p in "${ALT_LIST[@]+"${ALT_LIST[@]}"}"; do
    UP+=("iptables -t nat -A PREROUTING -i ${WAN_IF} -p udp --dport ${p} -j REDIRECT --to-ports ${WG_PORT}")
    DOWN+=("iptables -t nat -D PREROUTING -i ${WAN_IF} -p udp --dport ${p} -j REDIRECT --to-ports ${WG_PORT} || true")
done
{
    echo "[Interface]"
    echo "Address = ${SERVER_VPN_IP}/${VPN_SUBNET_CIDR}"
    echo "ListenPort = ${WG_PORT}"
    echo "MTU = ${WG_MTU}"
    echo "PrivateKey = ${SERVER_PRIV}"
    for line in "${UP[@]}"; do echo "PostUp = ${line}"; done
    for line in "${DOWN[@]}"; do echo "PostDown = ${line}"; done
    echo
    echo "[Peer]"
    echo "# ${CLIENT_NAME}"
    echo "PublicKey = ${CLIENT_PUB}"
    echo "AllowedIPs = ${CLIENT_VPN_IP}/32"
} > "$WG_DIR/$WG_IF.conf"
chmod 600 "$WG_DIR/$WG_IF.conf"

echo "[5/8] فعال‌سازی IP Forwarding..."
cat > /etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
EOF
# عمداً sysctl --system اجرا نمی‌شود: آن همه‌ی تنظیمات سیستم را لود می‌کند و اگر یکی
# از آن‌ها (مثل net.core.default_qdisc) روی این کرنل وجود نداشته باشد خطا می‌دهد.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
    die "فعال‌سازی net.ipv4.ip_forward ناموفق بود."
fi

echo "[6/8] باز کردن پورت‌ها و اجرای سرویس..."
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null || true)
    if grep -q "^Status: active" <<<"$UFW_STATUS"; then
        UFW_ACTIVE=1
        for p in $UDP_PORTS; do
            ufw allow "${p}/udp" >/dev/null
        done
    fi
fi
systemctl enable "wg-quick@${WG_IF}" >/dev/null 2>&1
if ! systemctl restart "wg-quick@${WG_IF}"; then
    echo "❌ سرویس wg-quick@${WG_IF} بالا نیامد. آخرین لاگ‌ها:" >&2
    journalctl -u "wg-quick@${WG_IF}" --no-pager -n 20 >&2 || true
    echo "   اگر خطا درباره iptables، nat یا REDIRECT بود، کرنل VPS آن را پشتیبانی نمی‌کند؛" >&2
    echo "   با  ALT_PORTS=\"\"  دوباره اجرا کنید:  sudo ALT_PORTS=\"\" bash wg-setup.sh" >&2
    exit 1
fi

echo "[7/8] ساخت کانفیگ‌های کلاینت..."
CLIENT_FILES=("${CLIENT_NAME}.conf:${WG_PORT}")
write_client_conf "$CLIENT_DIR/${CLIENT_NAME}.conf" "$WG_PORT"
for p in "${ALT_LIST[@]+"${ALT_LIST[@]}"}"; do
    write_client_conf "$CLIENT_DIR/${CLIENT_NAME}-p${p}.conf" "$p"
    CLIENT_FILES+=("${CLIENT_NAME}-p${p}.conf:${p}")
done

echo
echo "✅ WireGuard آماده است."
wg show "$WG_IF"
echo
echo "----- کانفیگ اصلی (${CLIENT_NAME}.conf) -----"
cat "$CLIENT_DIR/${CLIENT_NAME}.conf"
echo "---------------------------------------------"
if command -v qrencode >/dev/null 2>&1; then
    echo
    qrencode -t ansiutf8 < "$CLIENT_DIR/${CLIENT_NAME}.conf"
fi
echo

if [[ "$SUB_ENABLE" == "1" ]]; then
    STAGE="sub"
    echo "[8/8] ساخت لینک دانلود (ساب)..."
    setup_sub
    STAGE="main"
else
    echo "[8/8] لینک دانلود غیرفعال است (SUB_ENABLE=0)."
fi

echo
echo "════════════════ خلاصه ════════════════"
echo "فایل‌های کلاینت (پوشه ${CLIENT_DIR}):"
for entry in "${CLIENT_FILES[@]}"; do
    echo "  ${entry%%:*}   ←   UDP ${entry##*:}"
done
echo
if [[ "$SUB_ENABLE" == "1" ]]; then
    echo "🔗 لینک دانلود (ساب):"
    echo "   ${SUB_BASE}/"
    echo "   دانلود مستقیم کانفیگ اصلی: ${SUB_BASE}/${CLIENT_NAME}.conf"
    if [[ "$SUB_TTL_HOURS" == "0" ]]; then
        echo "   لینک دائمی است. خاموش کردن: systemctl disable --now wg-sub"
    else
        echo "   تا ${SUB_TTL_HOURS} ساعت دیگر فعال است و خودکار خاموش می‌شود."
        echo "   فعال‌سازی دوباره: systemctl restart wg-sub   |   خاموش کردن: systemctl stop wg-sub"
    fi
    echo "   (لینک‌ها در فایل ${CLIENT_DIR}/sub-link.txt هم ذخیره شده‌اند)"
    qrencode_ok=0
    if command -v qrencode >/dev/null 2>&1; then
        qrencode_ok=1
    fi
    if [[ "$qrencode_ok" == "1" ]]; then
        echo
        qrencode -t ansiutf8 "${SUB_BASE}/"
    fi
    echo
    echo "⚠️ گواهی self-signed است؛ مرورگر هشدار می‌دهد: Advanced ← Proceed."
    echo "⚠️ کانفیگ‌ها کلید خصوصی دارند؛ لینک را به کسی ندهید."
    echo "ℹ️ لینک روی همین IP است. اگر از اینترنت شما باز نشد، یعنی IP یا پورت فیلتر است؛"
    echo "   متن/QR کانفیگ بالا را مستقیم استفاده کنید یا SUB_PORT=8443 را امتحان کنید."
    echo
fi
echo "🔓 این پورت‌ها را در فایروال پنل VPS هم باز کنید:"
echo "   UDP: ${UDP_PORTS}"
if [[ "$SUB_ENABLE" == "1" ]]; then
    echo "   TCP: ${SUB_PORT_USE}"
fi
echo
echo "اگر یک پورت وصل نشد، فایل کانفیگ پورت بعدی را امتحان کنید."
