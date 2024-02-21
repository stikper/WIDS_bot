import os
import pyshark
import websockets
import asyncio
import sys
import time
from threading import Timer
import json


async def handler(ws):
    print(json.dumps(packets_counter))
    message = await ws.recv()
    if message == "get_pkt_cnt":
        await ws.send(json.dumps(packets_counter))

def prt(packet):
    print(packet.wlan.ta if hasattr(packet.wlan, 'ta') else "_",  packet.wlan.fc_type_subtype.showname, packet.wlan.ra if hasattr(packet.wlan, 'ra') else "_")
    print(packets_counter)

def refresh():
    global packets_counter
    global packets_list
    if len(packets_list) == 0: return Timer(1, refresh).start()
    while time.time() - packets_list[0][0] > 10:
        packets_counter[packets_list[0][1].wlan.fc_type_subtype] -= 1
        packets_list.pop(0)
    Timer(1, refresh).start()


def print_callback(packet):
    time_of_arrival = float(packet.frame_info.time_epoch)
    type_num = packet.wlan.fc_type_subtype
    if type_num in packets_counter: packets_counter[type_num] += 1
    else: packets_counter[type_num] = 1
    packets_list.append([time_of_arrival, packet])
    match packet.wlan.fc_type_subtype:
        case "0x0000": # Type/Subtype: Association Request (0x0000)
            prt(packet)
        case "0x0001": # Type/Subtype: Association Response (0x0001)
            prt(packet)
        case "0x0004": # Type/Subtype: Probe Request (0x0004)
            return
        case "0x0005": # Type/Subtype: Probe Response (0x0005)
            return
        case "0x0008": # Type/Subtype: Beacon frame (0x0008)
            prt(packet)
        case "0x000b": # Type/Subtype: Authentication (0x000b)
            prt(packet)
        case "0x000c": # Type/Subtype: Deauthentication (0x000c)
            prt(packet)
        case "0x000d": # Type/Subtype: Action (0x000d)
            return
        case "0x001b":  # Type/Subtype: Request-to-send (0x001b)
            return
        case "0x001c": # Type/Subtype: Clear-to-send (0x001c)
            return
        case "0x001d": # Type/Subtype: Acknowledgement (0x001d)
            return
        case "0x001e": # Type/Subtype: CF-End (Control-frame) (0x001e)
            return
        case "0x0020": # Type/Subtype: Data (0x0020)
            return
        case "0x0024": # Type/Subtype: Null function (No data) (0x0024)
            return
        case "0x0028": # Type/Subtype: QoS Data (0x0028)
            return
        case "0x002c": # Type/Subtype: QoS Null function (No data) (0x002c)
            return
        case _:
            prt(packet)


if __name__ == "__main__":

    interface = sys.argv[1]
    bssid = sys.argv[2]
    channel = sys.argv[3]
    os.system(f'sudo iwconfig {interface} channel {channel}')

    packets_counter: dict[str, int] = {} # (Packet_type) => cnt
    packets_list = []
    refresh()

    capture = pyshark.LiveCapture(interface=f'{interface}', bpf_filter=f'wlan host {bssid}')

    start_server = websockets.serve(handler, "localhost", 8765)
    asyncio.get_event_loop().run_until_complete(start_server)
    capture.apply_on_packets(print_callback)
    asyncio.get_event_loop().run_forever()


    # for packet in capture.sniff_continuously():
    #     print_callback(packet)
