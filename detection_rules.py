from collections import defaultdict
from datetime import datetime
import time

# Store the time of recent packets from each source IP
packet_times = defaultdict(list)

# Detection settings
PACKET_LIMIT = 20
TIME_WINDOW = 10


def check_packet_rate(source_ip):
    current_time = time.time()

    # Remove old packet timestamps
    packet_times[source_ip] = [
        t for t in packet_times[source_ip]
        if current_time - t <= TIME_WINDOW
    ]

    # Add current packet
    packet_times[source_ip].append(current_time)

    # Detect unusually high packet rate
    if len(packet_times[source_ip]) > PACKET_LIMIT:
        return (
            f"[ALERT] High packet rate detected from {source_ip} "
            f"({len(packet_times[source_ip])} packets in {TIME_WINDOW} seconds)"
        )

    return None


def create_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = f"{timestamp} - {message}"

    print(alert)

    with open("alerts.log", "a") as file:
        file.write(alert + "\n")