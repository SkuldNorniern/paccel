"""
Generate test pcap/pcapng fixtures used by the paccel test suite.

Run once (or on CI via `python3 tests/generate_pcaps.py`) to (re)create all files
under tests/pcaps/happy-path/.

Requires scapy:  pip install scapy
"""
import os, sys

try:
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
        ARP, DNS, DNSQR, DNSRR, Raw, wrpcap, wrpcapng,
    )
except ImportError:
    print("scapy not found — install with: pip install scapy", file=sys.stderr)
    sys.exit(1)

OUTDIR = os.path.join(os.path.dirname(__file__), "pcaps", "happy-path")
os.makedirs(OUTDIR, exist_ok=True)

def out(name):
    return os.path.join(OUTDIR, name)


# ── DNS UDP/IPv4 query ──────────────────────────────────────────────────
pkt_dns_q = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") /
    IP(src="192.168.1.1", dst="8.8.8.8", ttl=64) /
    UDP(sport=12345, dport=53) /
    DNS(id=0x1234, rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))
)
wrpcap(out("dns_udp_ipv4.pcap"), [pkt_dns_q])

# ── DNS UDP/IPv4 response ───────────────────────────────────────────────
pkt_dns_r = (
    Ether(dst="aa:bb:cc:dd:ee:ff", src="01:02:03:04:05:06") /
    IP(src="8.8.8.8", dst="192.168.1.1", ttl=55) /
    UDP(sport=53, dport=12345) /
    DNS(
        id=0x1234, qr=1, aa=0, rd=1, ra=1,
        qd=DNSQR(qname="www.example.com", qtype="A"),
        an=DNSRR(rrname="www.example.com", type="A",
                 rdata="93.184.216.34", ttl=300),
    )
)
wrpcap(out("dns_response_ipv4.pcap"), [pkt_dns_r])

# ── TCP SYN/IPv4 with options ───────────────────────────────────────────
pkt_tcp_syn = (
    Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66") /
    IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) /
    TCP(
        sport=54321, dport=80, flags="S", seq=0xDEADBEEF,
        options=[
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (100, 0)),
            ("NOP", None),
            ("WScale", 7),
        ],
    )
)
wrpcap(out("tcp_syn_ipv4.pcap"), [pkt_tcp_syn])

# ── ARP request ─────────────────────────────────────────────────────────
pkt_arp = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") /
    ARP(
        op="who-has",
        psrc="192.168.1.100", pdst="192.168.1.1",
        hwsrc="aa:bb:cc:dd:ee:ff", hwdst="00:00:00:00:00:00",
    )
)
wrpcap(out("arp_request.pcap"), [pkt_arp])

# ── ICMP echo request/IPv4 ──────────────────────────────────────────────
pkt_icmp = (
    Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66") /
    IP(src="192.168.1.1", dst="192.168.1.2", ttl=64) /
    ICMP(type=8, code=0, id=0x1337, seq=1) /
    Raw(b"abcdefghijklmnop")
)
wrpcap(out("icmp_echo_ipv4.pcap"), [pkt_icmp])

# ── ICMPv6 echo request/IPv6 ────────────────────────────────────────────
pkt_icmpv6 = (
    Ether(dst="33:33:00:00:00:01", src="aa:bb:cc:dd:ee:ff") /
    IPv6(src="fe80::1", dst="ff02::1", hlim=255) /
    ICMPv6EchoRequest(id=1, seq=1) /
    Raw(b"Hello IPv6")
)
wrpcap(out("icmpv6_echo_ipv6.pcap"), [pkt_icmpv6])

# ── DNS query — pcapng format ────────────────────────────────────────────
wrpcapng(out("dns_udp_ipv4.pcapng"), [pkt_dns_q])

# ── Multi-frame pcap (query + response + TCP SYN) ───────────────────────
wrpcap(out("multi_frame.pcap"), [pkt_dns_q, pkt_dns_r, pkt_tcp_syn])

print("Generated pcap fixtures in", OUTDIR)
for name in sorted(os.listdir(OUTDIR)):
    size = os.path.getsize(os.path.join(OUTDIR, name))
    print(f"  {name:40s}  {size:5d} bytes")
