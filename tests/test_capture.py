import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scapy.all import Ether, IP, TCP, UDP
from capture import parse_packet

def test_tcp_packet():
    """Parser correctly extracts fields from a TCP packet."""
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
          IP(src="192.168.1.1", dst="8.8.8.8") / \
          TCP(sport=12345, dport=443)
    result = parse_packet(pkt)
    assert result is not None
    assert result['mac_src']  == "aa:bb:cc:dd:ee:01"
    assert result['mac_dst']  == "aa:bb:cc:dd:ee:02"
    assert result['ip_src']   == "192.168.1.1"
    assert result['ip_dst']   == "8.8.8.8"
    assert result['port_src'] == 12345
    assert result['port_dst'] == 443
    assert result['protocol'] == "TCP"
    print("PASS: TCP packet parsed correctly")

def test_udp_packet():
    """Parser correctly extracts fields from a UDP packet."""
    pkt = Ether(src="aa:bb:cc:dd:ee:03", dst="aa:bb:cc:dd:ee:04") / \
          IP(src="192.168.1.2", dst="1.1.1.1") / \
          UDP(sport=54321, dport=53)
    result = parse_packet(pkt)
    assert result is not None
    assert result['protocol'] == "UDP"
    assert result['port_dst'] == 53
    print("PASS: UDP packet parsed correctly")

def test_non_ip_packet_returns_none():
    """Parser returns None for non-IP packets."""
    pkt = Ether(src="aa:bb:cc:dd:ee:05", dst="aa:bb:cc:dd:ee:06")
    result = parse_packet(pkt)
    assert result is None
    print("PASS: Non-IP packet correctly returns None")

if __name__ == '__main__':
    test_tcp_packet()
    test_udp_packet()
    test_non_ip_packet_returns_none()
    print("\nAll tests passed.")