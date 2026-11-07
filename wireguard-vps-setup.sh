#!/usr/bin/env bash
set -Eeuo pipefail

WG_DIR="/etc/wireguard"
WG_IFACE="wg0"
WG_CONF="${WG_DIR}/${WG_IFACE}.conf"
SYSCTL_CONF="/etc/sysctl.d/99-wireguard-ip-forward.conf"
CLIENT_CONF="/root/wg-client.conf"

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

valid_ipv4_cidr_list() {
  local list="$1" item ip prefix octet
  local -a items octets

  [[ "$list" =~ ^[0-9./,]+$ ]] || return 1
  [[ "$list" != ,* && "$list" != *, && "$list" != *,,* ]] || return 1
  IFS=',' read -r -a items <<< "$list"

  for item in "${items[@]}"; do
    if [[ "$item" == */* ]]; then
      [[ "$item" != */*/* ]] || return 1
      ip="${item%/*}"
      prefix="${item#*/}"
      [[ "$prefix" =~ ^[0-9]{1,2}$ ]] || return 1
      ((10#$prefix <= 32)) || return 1
    else
      ip="$item"
    fi

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
      ((10#$octet <= 255)) || return 1
    done
  done
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this script as root: sudo bash $0"
[[ -r /etc/os-release ]] || die "Cannot identify the Linux distribution."
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" ]] || die "This script supports Debian and Ubuntu only."
command -v apt-get >/dev/null 2>&1 || die "apt-get is required."
command -v systemctl >/dev/null 2>&1 || die "systemd is required."
command -v ip >/dev/null 2>&1 || die "The ip command is required."

[[ ! -e "$WG_CONF" ]] || die "$WG_CONF already exists; refusing to overwrite it."
[[ ! -e "$SYSCTL_CONF" ]] || die "$SYSCTL_CONF already exists; inspect it before continuing."
[[ ! -e "$CLIENT_CONF" ]] || die "$CLIENT_CONF already exists; move it before continuing."
if ip link show "$WG_IFACE" >/dev/null 2>&1; then
  die "The $WG_IFACE network interface already exists."
fi

read -r -p "VPS public IPv4 address or DNS name (without port): " SERVER_ENDPOINT
[[ "$SERVER_ENDPOINT" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "Enter a public IPv4 address or DNS name, not an IPv6 address or URL."

read -r -p "WireGuard UDP port [51820]: " SERVER_PORT
SERVER_PORT="${SERVER_PORT:-51820}"
[[ "$SERVER_PORT" =~ ^[0-9]{1,5}$ ]] || die "The port must be a number from 1 to 65535."
SERVER_PORT=$((10#$SERVER_PORT))
((SERVER_PORT >= 1 && SERVER_PORT <= 65535)) || die "The port must be a number from 1 to 65535."

printf '\nClient routing mode:\n'
printf '  1) Full tunnel: all IPv4 traffic goes through the VPS (default).\n'
printf '  2) Gaming split tunnel: only the exact game-server IPv4/CIDRs entered below.\n'
read -r -p "Choose [1]: " ROUTE_MODE
case "${ROUTE_MODE:-1}" in
  1)
    CLIENT_ALLOWED_IPS="0.0.0.0/0"
    ROUTE_DESCRIPTION="full tunnel"
    ;;
  2)
    read -r -p "Game-server IPv4/CIDRs, comma-separated (for example 203.0.113.8/32): " CLIENT_ALLOWED_IPS
    valid_ipv4_cidr_list "$CLIENT_ALLOWED_IPS" || die "Enter valid IPv4 addresses/CIDRs separated by commas."
    ROUTE_DESCRIPTION="gaming split tunnel: $CLIENT_ALLOWED_IPS"
    ;;
  *)
    die "Choose 1 or 2."
    ;;
esac

printf '\nThis will install WireGuard, enable IPv4 forwarding, and start wg0.\n'
read -r -p "Continue? [y/N]: " CONFIRM
[[ "${CONFIRM,,}" == "y" || "${CONFIRM,,}" == "yes" ]] || exit 0

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y wireguard wireguard-tools iptables
unset DEBIAN_FRONTEND

for command_name in wg wg-quick iptables; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found after installation: $command_name"
done

WAN_IFACE="$(ip -4 route show default | awk 'NR == 1 {print $5}')"
[[ -n "$WAN_IFACE" ]] || die "Could not detect the VPS default network interface."

install -d -o root -g root -m 700 "$WG_DIR"
umask 077
SERVER_PRIVATE_KEY="$(wg genkey)"
SERVER_PUBLIC_KEY="$(printf '%s' "$SERVER_PRIVATE_KEY" | wg pubkey)"
CLIENT_PRIVATE_KEY="$(wg genkey)"
CLIENT_PUBLIC_KEY="$(printf '%s' "$CLIENT_PRIVATE_KEY" | wg pubkey)"

cat > "$WG_CONF" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $WAN_IFACE -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.66.66.2/32
EOF
chmod 600 "$WG_CONF"

cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.66.66.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_ENDPOINT:$SERVER_PORT
AllowedIPs = $CLIENT_ALLOWED_IPS
PersistentKeepalive = 25
EOF
chmod 600 "$CLIENT_CONF"

printf 'net.ipv4.ip_forward=1\n' > "$SYSCTL_CONF"
chmod 644 "$SYSCTL_CONF"
sysctl --system >/dev/null

if command -v ufw >/dev/null 2>&1; then
  UFW_STATUS="$(ufw status 2>/dev/null || true)"
  if [[ "$UFW_STATUS" == *"Status: active"* ]]; then
    ufw allow "${SERVER_PORT}/udp"
  fi
fi

wg-quick strip "$WG_IFACE" >/dev/null
systemctl enable --now "wg-quick@${WG_IFACE}"

printf '\nWireGuard is running on UDP port %s.\n' "$SERVER_PORT"
printf 'Client profile: %s (contains a private key; keep it secret).\n' "$CLIENT_CONF"
printf 'Client routing: %s\n' "$ROUTE_DESCRIPTION"
printf 'If your VPS provider has a cloud firewall, allow inbound UDP %s there too.\n' "$SERVER_PORT"
printf 'This setup is IPv4-only. For gaming, compare ping with and without the VPN; a VPN can increase latency.\n'
