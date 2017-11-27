import socket,struct,binascii,os,sys, time
from general import *
from pcap import Pcap
from ethernet import Ethernet
from ipv4 import IPv4
from tcp import TCP
from http import HTTP
from udp import UDP

if os.name == "nt":
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("YOUR_INTERFACE_IP",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
else:
    s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

pcap = Pcap('capture.pcap')

# Maximum packet read number.

count_pkt = 0

if len(sys.argv) == 1:
    sys.exit("Have to pass full packet number.")
else:
    max_pkt = int(sys.argv[1])

while True:
    pkt, addr = s.recvfrom(65565)
    pcap.write(pkt)
    eth = Ethernet(pkt)
    t = time.localtime()

    print("%d's Packet." % count_pkt)
    print('Time: {}.{}.{}, {}.{}.{}'.format(t.tm_mon, t.tm_mday, t.tm_year, t.tm_hour, t.tm_min,
    t.tm_sec))
    print('Ethernet Frame:')
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac,
    eth.proto))

    # IPv4
    if eth.proto == 8:
        ipv4 = IPv4(eth.data)
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version,
        ipv4.header_length, ipv4.ttl))
        print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src,
        ipv4.target))
        
        # TCP
        if ipv4.proto == 6:
            tcp = TCP(ipv4.data)
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port,
            tcp.dest_port))
            print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence,
            tcp.acknowledgment))
            print(TAB_2 + 'Flags:')
            print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack,
            tcp.flag_psh))
            print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn,
            tcp.flag_fin))

            if len(tcp.data) > 0 :
                # HTTP
                if tcp.src_port == 80 or tcp.dest_port == 80:
                    print(TAB_2 + 'HTTP Data:')
                    try:
                        http = HTTP(tcp.data)
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            print(DATA_TAB_3 + str(line))
                    except:
                        print(format_multi_line(DATA_TAB_3, tcp.data))
                else:
                    print(TAB_2 + 'TCP Data:')
                    print(format_multi_line(DATA_TAB_3, tcp.data))
        elif ipv4.proto == 17:
            udp = UDP(ipv4.data)
            print(TAB_1 + 'UDP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port,
            udp.dest_port, udp.size))

    if count_pkt >= max_pkt:
        break
    else:
        count_pkt += 1

pcap.close()



    
