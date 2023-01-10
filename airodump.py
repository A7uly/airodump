#!/usr/bin/python
# python3
# Writer: Subin Jo

import socket, sys, struct, os
APlist = {}

class AP:
    def __init__(self, bssid, pwr, ssid):
        self.bssid = bssid
        self.beacons = 1
        self.ssid = ssid
        self.pwr = pwr


def packetDump(lan):
    packet = None
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((lan, 0x0003))
        packet = s.recvfrom(2048)[0]
    except:
        print("Fail")

    return packet


def packetParse(pkt):
    rt_hlen = struct.unpack('>bb', pkt[2:4])
    if rt_hlen == 0:
        return None

    pwr = int.from_bytes(pkt[18:19], "big",signed=True)
    #print("pwr: ", pwr)
    f_80211 = pkt[rt_hlen[0]:]

    beacon_flag = f_80211[0:1]
    #check beacon frame
    if beacon_flag == b'\x80':
        print("[beacon_Frame Right]")
        bssid = f_80211[16:22]
        if bssid not in APlist.keys():
            ssid_len = int.from_bytes(pkt[61:62], "little")
            ssid = pkt[62:62+ssid_len].decode('utf-8')
            new_AP = AP(bssid, pwr, ssid)
            #print("It's a new AP")
            APlist[bssid] = new_AP
        else:
            #print("It's one of old AP")
            temp = APlist[bssid]
            temp.beacons += 1
            APlist[bssid] = temp

    else:
        print("It's not beacon_Frame")


def printAP():
    os.system('clear')
    print('BSSID               PWR     BEACONS      ESSID')
    for i in APlist.keys():
        bssid = APlist[i].bssid.hex()
        bssid = bssid[0:2] + ":" + bssid[2:4] + ":" + bssid[4:6] + ":" + bssid[6:8] + ":" + bssid[8:10] + ":" + bssid[10:12]
        pwr = APlist[i].pwr
        beacons = APlist[i].beacons
        ssid = APlist[i].ssid
        print(bssid, "  ", pwr, "\t", beacons, "\t", ssid)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Insufficient arguments")
        sys.exit()
    lan = sys.argv[1]

    while True:
        pkt = packetDump(lan)
        packetParse(pkt)
        printAP()
