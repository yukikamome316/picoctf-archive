#!/usr/bin/env python3
import sys
import re
import base64
from scapy.all import rdpcap, TCP


def extract_tcp_payloads_with_time(pcap_file):
    """
    Extract TCP payloads with timestamps from packets in a PCAP file using Scapy.

    Args:
        pcap_file (str): Path to the PCAP file to analyze

    Returns:
        list: List of dictionaries with timestamp, packet number, and payload info
    """
    payloads_with_time = []
    packet_count = 0

    try:
        packets = rdpcap(pcap_file)
        for i, packet in enumerate(packets):
            packet_count += 1
            timestamp = float(packet.time)

            if TCP in packet:
                tcp_payload = bytes(packet[TCP].payload)
                if tcp_payload:
                    try:
                        decoded = base64.b64decode(tcp_payload)
                        decoded_text = decoded.decode("utf-8", errors="replace")
                    except Exception:
                        decoded = None
                        decoded_text = None

                    payloads_with_time.append(
                        {
                            "timestamp": timestamp,
                            "packet_num": packet_count,
                            "raw": tcp_payload,
                            "decoded": decoded,
                            "decoded_text": decoded_text,
                        }
                    )

        # Sort by timestamp
        payloads_with_time.sort(key=lambda x: x["timestamp"])

    except Exception as e:
        print(f"Error processing PCAP file: {str(e)}")

    return payloads_with_time, packet_count


def parse_wireshark_output(output_text):
    """
    Parse Wireshark text output to extract packet info with timestamps.

    Args:
        output_text (str): Wireshark output text

    Returns:
        list: List of dictionaries with timestamp, packet number, and other info
    """
    parsed_packets = []

    # Regular expression to match Wireshark output lines
    pattern = r"(\d+) (\d+:\d+:\d+\.\d+) (\S+) (\S+) (\w+) (\d+)(.*)"

    lines = output_text.strip().split("\n")
    for line in lines:
        match = re.match(pattern, line)
        if match:
            packet_num = int(match.group(1))
            timestamp = match.group(2)
            src_ip = match.group(3)
            dst_ip = match.group(4)
            protocol = match.group(5)
            length = int(match.group(6))
            rest = match.group(7)

            # Extract specific info like SYN flag, sequence number, etc.
            syn_match = re.search(r"\[SYN\]", rest)
            seq_match = re.search(r"Seq=(\d+)", rest)
            len_match = re.search(r"Len=(\d+)", rest)

            parsed_packets.append(
                {
                    "packet_num": packet_num,
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "length": length,
                    "is_syn": bool(syn_match),
                    "seq": int(seq_match.group(1)) if seq_match else None,
                    "payload_len": int(len_match.group(1)) if len_match else None,
                }
            )

    return parsed_packets


def decode_base64_payload(payload):
    """
    Decode a BASE64 encoded payload.

    Args:
        payload (bytes or str): The payload to decode

    Returns:
        tuple: (success, decoded_text, decoded_hex)
    """
    try:
        if isinstance(payload, str):
            # Try to convert hex string to bytes
            try:
                payload = bytes.fromhex(payload)
            except ValueError:
                payload = payload.encode("ascii")

        decoded = base64.b64decode(payload)

        try:
            decoded_text = decoded.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            decoded_text = None

        return True, decoded_text, decoded.hex()
    except Exception as e:
        return False, str(e), None


def process_wireshark_and_payloads(wireshark_output, decoded_payloads):
    """
    Process Wireshark output and decoded payloads together.

    Args:
        wireshark_output (str): Wireshark output text
        decoded_payloads (dict): Dictionary mapping packet numbers to decoded payloads

    Returns:
        list: Combined and sorted packet information
    """
    parsed_packets = parse_wireshark_output(wireshark_output)

    for packet in parsed_packets:
        packet_num = packet["packet_num"]
        if packet_num in decoded_payloads:
            packet["payload"] = decoded_payloads[packet_num]

    # Sort by timestamp
    parsed_packets.sort(key=lambda x: x["timestamp"])

    return parsed_packets


def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <pcap_file> [wireshark_output_file]")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # Process PCAP file if it exists
    try:
        payloads, total_packets = extract_tcp_payloads_with_time(pcap_file)

        print(f"Sorted packets by timestamp (total: {len(payloads)}):")

        ordered_decoded_text = []

        for i, payload_info in enumerate(payloads):
            timestamp = payload_info["timestamp"]
            packet_num = payload_info["packet_num"]
            raw = payload_info["raw"]
            decoded = payload_info["decoded"]

            if decoded and payload_info["decoded_text"]:
                decoded_text = payload_info["decoded_text"]
                ordered_decoded_text.append(decoded_text)

                print(
                    f"{i + 1:2d}. Packet #{packet_num} (time: {timestamp:.6f}): {raw.decode('ascii', 'replace')} -> {decoded_text}"
                )
            else:
                print(
                    f"{i + 1:2d}. Packet #{packet_num} (time: {timestamp:.6f}): {raw.decode('ascii', 'replace')} -> [decode failed]"
                )

        # Print the combined result
        combined = "".join(ordered_decoded_text)
        print("\nCombined decoded text in timestamp order:")
        print(combined)

    except FileNotFoundError:
        print(f"Error: PCAP file '{pcap_file}' not found.")
    except Exception as e:
        print(f"Error processing file: {str(e)}")


def process_decoded_payloads_list():
    # This is a manual list of decoded payloads from the previously provided output
    decoded_payloads = [
        {"packet_num": 1, "decoded": "nt_th4t"},
        {"packet_num": 2, "decoded": "Zν��", "hex": "5acebd85cf"},
        {"packet_num": 3, "decoded": "8��x�", "hex": "388fe978ac"},
        {"packet_num": 4, "decoded": "s����", "hex": "73ae8597e4"},
        {"packet_num": 5, "decoded": "Ȱ�", "hex": "c8b00cf104"},
        {"packet_num": 6, "decoded": "���", "hex": "fbfff299a9"},
        {"packet_num": 7, "decoded": "}", "hex": "7d"},
        {"packet_num": 8, "decoded": "bh_4r_3", "hex": "62685f34725f33"},
        {"packet_num": 9, "decoded": "k7[", "hex": "6b371c1b5b"},
        {"packet_num": 10, "decoded": "", "hex": ""},
    ]

    # Sort by packet_num (assuming this is the original timestamp order)
    decoded_payloads.sort(key=lambda x: x["packet_num"])

    readable_parts = []
    for payload in decoded_payloads:
        if "decoded" in payload and isinstance(payload["decoded"], str):
            text = payload["decoded"]
            if re.search(r"[a-zA-Z0-9_{}]", text):
                readable_parts.append(text)

    combined = "".join(readable_parts)
    print("\nCombined decoded parts that look like flag components:")
    print(combined)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        main()
    else:
        process_decoded_payloads_list()
