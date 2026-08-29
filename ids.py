from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import time

# -------------------------------
# IDS Configuration
# -------------------------------

PACKET_LIMIT = 20
TIME_WINDOW = 10

packet_count = defaultdict(list)

# -------------------------------
# Create Alert
# -------------------------------

def create_alert(source_ip, count):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = (
        f"[{timestamp}] ALERT: High packet rate detected | "
        f"Source: {source_ip} | "
        f"Packets: {count} in {TIME_WINDOW} seconds"
    )

    print("\n" + alert)

    with open("Alerts.log", "a") as file:
        file.write(alert + "\n")


# -------------------------------
# Check Packet Rate
# -------------------------------

def check_packet_rate(source_ip):
    current_time = time.time()

    # Store current packet time
    packet_count[source_ip].append(current_time)

    # Remove packets outside the time window
    packet_count[source_ip] = [
        packet_time
        for packet_time in packet_count[source_ip]
        if current_time - packet_time <= TIME_WINDOW
    ]

    count = len(packet_count[source_ip])

    # Check whether packet limit is exceeded
    if count > PACKET_LIMIT:
        create_alert(source_ip, count)

        # Clear list to prevent continuous alerts
        packet_count[source_ip].clear()


# -------------------------------
# Process Captured Packet
# -------------------------------

def process_packet(packet):

    if IP in packet:

        source = packet[IP].src
        destination = packet[IP].dst

        # Identify protocol
        if TCP in packet:
            protocol = "TCP"

        elif UDP in packet:
            protocol = "UDP"

        elif ICMP in packet:
            protocol = "ICMP"

        else:
            protocol = "Other"

        print(
            f"Source: {source} | "
            f"Destination: {destination} | "
            f"Protocol: {protocol}"
        )

        # Apply detection rule
        check_packet_rate(source)


# -------------------------------
# Main Program
# -------------------------------

def main():

    print("=" * 60)
    print("      NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)

    print(f"Packet Limit : {PACKET_LIMIT}")
    print(f"Time Window  : {TIME_WINDOW} seconds")
    print("\nMonitoring network traffic...")
    print("Press CTRL+C to stop.\n")

    try:

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n")
        print("IDS monitoring stopped.")

    except Exception as error:

        print("\nError:", error)


# -------------------------------
# Start Program
# -------------------------------

if __name__ == "__main__":
    main()