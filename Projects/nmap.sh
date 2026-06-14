#!/bin/bash

# ============================================
# nmap-enum.sh — Two-Phase Nmap Enumeration
# TCP: full port range quick scan → deep scan
# UDP: top 1000 quick scan → deep scan
# ============================================

# --- Color output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Get target from user ---
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}       Nmap Two-Phase Enumeration       ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
read -rp "Enter target IP or range: " IP

if [[ -z "$IP" ]]; then
    echo -e "${RED}[!] No target provided. Exiting.${NC}"
    exit 1
fi

# --- Create results directory ---
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="nmap_results_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

echo ""
echo -e "${GREEN}[+] Target: ${IP}${NC}"
echo -e "${GREEN}[+] Results directory: ${RESULTS_DIR}${NC}"
echo ""

# ============================================
# PHASE 0: Host Discovery
# ============================================
echo -e "${YELLOW}[*] Phase 0: Host Discovery (-sn)${NC}"
nmap -sn "$IP" -oG "$RESULTS_DIR/host_discovery.gnmap" 2>/dev/null

# Parse live hosts
LIVE_HOSTS=$(grep "Status: Up" "$RESULTS_DIR/host_discovery.gnmap" | awk '{print $2}')

if [[ -z "$LIVE_HOSTS" ]]; then
    echo -e "${RED}[!] No live hosts found. Exiting.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Live hosts found:${NC}"
echo "$LIVE_HOSTS" | while read -r host; do echo -e "    ${CYAN}$host${NC}"; done
echo ""

# Write live hosts to a file for nmap -iL
HOSTS_FILE="$RESULTS_DIR/live_hosts.txt"
echo "$LIVE_HOSTS" > "$HOSTS_FILE"

# ============================================
# PHASE 1a: TCP Quick Scan (all ports)
# ============================================
echo -e "${YELLOW}[*] Phase 1a: TCP Quick Scan — all 65535 ports${NC}"
nmap -sS -p- --min-rate 5000 --open -iL "$HOSTS_FILE" \
    -oG "$RESULTS_DIR/tcp_quick.gnmap" \
    -oN "$RESULTS_DIR/tcp_quick.nmap" 2>/dev/null

# Parse open TCP ports
TCP_PORTS=$(grep "/open/" "$RESULTS_DIR/tcp_quick.gnmap" \
    | grep -oP '\d+/open' \
    | cut -d'/' -f1 \
    | sort -un \
    | paste -sd ',')

if [[ -z "$TCP_PORTS" ]]; then
    echo -e "${RED}[!] No open TCP ports found.${NC}"
else
    echo -e "${GREEN}[+] Open TCP ports: ${TCP_PORTS}${NC}"
    echo ""

    # ============================================
    # PHASE 2a: TCP Deep Scan (version + vuln)
    # ============================================
    echo -e "${YELLOW}[*] Phase 2a: TCP Deep Scan — version detection + vuln scripts${NC}"
    nmap -sCV -p "$TCP_PORTS" --script vuln -iL "$HOSTS_FILE" \
        -oN "$RESULTS_DIR/tcp_deep.nmap" \
        -oX "$RESULTS_DIR/tcp_deep.xml" 2>/dev/null

    echo -e "${GREEN}[+] TCP deep scan complete.${NC}"
fi

echo ""

# ============================================
# PHASE 1b: UDP Quick Scan (top 1000)
# ============================================
echo -e "${YELLOW}[*] Phase 1b: UDP Quick Scan — top 1000 ports${NC}"
nmap -sU --top-ports 1000 --min-rate 5000 --open -iL "$HOSTS_FILE" \
    -oG "$RESULTS_DIR/udp_quick.gnmap" \
    -oN "$RESULTS_DIR/udp_quick.nmap" 2>/dev/null

# Parse open UDP ports
UDP_PORTS=$(grep "/open/" "$RESULTS_DIR/udp_quick.gnmap" \
    | grep -oP '\d+/open' \
    | cut -d'/' -f1 \
    | sort -un \
    | paste -sd ',')

if [[ -z "$UDP_PORTS" ]]; then
    echo -e "${RED}[!] No open UDP ports found.${NC}"
else
    echo -e "${GREEN}[+] Open UDP ports: ${UDP_PORTS}${NC}"
    echo ""

    # ============================================
    # PHASE 2b: UDP Deep Scan (version + vuln)
    # ============================================
    echo -e "${YELLOW}[*] Phase 2b: UDP Deep Scan — version detection + vuln scripts${NC}"
    nmap -sUCV -p "$UDP_PORTS" --script vuln -iL "$HOSTS_FILE" \
        -oN "$RESULTS_DIR/udp_deep.nmap" \
        -oX "$RESULTS_DIR/udp_deep.xml" 2>/dev/null

    echo -e "${GREEN}[+] UDP deep scan complete.${NC}"
fi

# ============================================
# Summary
# ============================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}            Scan Complete               ${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}[+] All results saved to: ${RESULTS_DIR}/${NC}"
echo ""
echo -e "  Host discovery:  ${RESULTS_DIR}/host_discovery.gnmap"
echo -e "  Live hosts list: ${RESULTS_DIR}/live_hosts.txt"
[[ -n "$TCP_PORTS" ]] && echo -e "  TCP quick scan:  ${RESULTS_DIR}/tcp_quick.nmap"
[[ -n "$TCP_PORTS" ]] && echo -e "  TCP deep scan:   ${RESULTS_DIR}/tcp_deep.nmap"
[[ -n "$UDP_PORTS" ]] && echo -e "  UDP quick scan:  ${RESULTS_DIR}/udp_quick.nmap"
[[ -n "$UDP_PORTS" ]] && echo -e "  UDP deep scan:   ${RESULTS_DIR}/udp_deep.nmap"
echo ""