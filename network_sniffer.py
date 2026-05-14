from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Packet process function
def process_packet(packet):

    print("\n===== New Packet Captured =====")

    # Check IP layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")

        # TCP Packet
        if packet.haslayer(TCP):
            print("Protocol Type  : TCP")

        # UDP Packet
        elif packet.haslayer(UDP):
            print("Protocol Type  : UDP")

        # Payload data
        if packet.payload:
            print(f"Payload        : {bytes(packet.payload)}")


# Start sniffing
print("Starting Network Sniffer...")

sniff(prn=process_packet, count=10)

print("Sniffing Finished!")