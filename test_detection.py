from detection_rules import check_packet_rate, create_alert

test_ip = "192.168.1.100"

print("Testing IDS detection rule...")

for i in range(21):
    alert = check_packet_rate(test_ip)

    if alert:
        create_alert(alert)

print("Detection rule test completed.")