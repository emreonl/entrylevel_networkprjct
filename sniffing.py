from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def capture_traffic():
    print("Starting capture on interface: en0")
    sniff(iface='en0', prn=packet_callback, count=100)

if __name__ == "__main__":
    capture_traffic()
