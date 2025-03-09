# This is a python script designed to test the firewall rules on my pfsense firewall.
# It leverages scapy to test the following ports:
#   - 53/UDP on dc01 (DNS)
#   - 445/TCP on dc01 (SMB)
#   - 80/TCP on apache1 (HTTP)
#   - 443/TCP on apache1 (HTTPS)
#   - 22/TCP on apache1 (SSH | this should never work, even though it is allowed on the apache1 firewall)
#   - 53/UDP on ns1 (DNS | this should never work, even though it is allowed on the ns1 firewall)
#   - 22/TCP on ns1 (SSH | this should never work, even though it is allowed on the ns1 firewall)
# In addition, it will test ICMP for the following machines:
#   - dc1
#   - apache1
#   - ns1
# This script is designed to (hopefully) be modified and adapted to other uses besides this lab.

from scapy.all import IP, ICMP, TCP, UDP, DNS, DNSQR, sr1


def test_icmp(host_dict: dict) -> None:
    print("-" * 50)
    print("Beginning ICMP testing:")
    for host, ip in host_dict.items():
        packet = IP(dst=ip) / ICMP(type=8, code=0)
        reply = sr1(packet, timeout=2, verbose=False)
        if reply:
            print(f"{host} ({ip}) is reachable by ICMP.")
        else:
            print(f"{host} ({ip}) is NOT reachable by ICMP.")
    return

def test_tcp (host_dict: dict) -> None:
    print("-" * 50)
    print("Beginning TCP testing:")
    for host, endpoint in host_dict.items():
        ip = endpoint[0]
        for port in endpoint[1]:
            packet = IP(dst=ip) / TCP(dport=port, flags="S")
            reply = sr1(packet, timeout=2, verbose=False)
            if reply:
                print(f"{host} ({ip}) is reachable on port {port}/TCP")
            else:
                print(f"{host} ({ip}) is NOT reachable on port {port}/TCP")
    return

def test_udp (host_dict: dict) -> None:
    print("-" * 50)
    print("Beginning UDP testing:")
    for host, endpoint in host_dict.items():
        ip = endpoint[0]
        for port in endpoint[1]:
            if port == 53:
                packet = IP(dst=ip) / UDP(dport=port) / DNS(qd=DNSQR(qname="itas.ca",qtype="A"))
                reply = sr1(packet, timeout=2, verbose=False)
                if reply:
                    print(f"{host} ({ip}) is reachable on port {port}/UDP")
                else:
                    print(f"{host} ({ip}) is NOT reachable on port {port}/UDP")
            else:
                print("This script is not capable of checking port {port}/UDP yet... {host}")
    return


icmp_host_dict = {
    "dc01":"192.168.224.5",
    "ns1":"192.168.224.10",
    "apache1":"192.168.224.20"
}
test_icmp(icmp_host_dict)

tcp_host_dict = {
    "dc01":["192.168.224.5", [445]],
    "apache1":["192.168.224.20", [22, 80, 443]],
    "ns1":["192.168.224.10", [22]]
}
test_tcp(tcp_host_dict)

udp_host_dict = {
    "dc01":["192.168.224.5", [53]],
    "ns1":["192.168.224.10", [53]]
}
test_udp(udp_host_dict)
