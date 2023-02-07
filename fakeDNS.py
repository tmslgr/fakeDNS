# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import sys, socket, argparse
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

hostdict = dict()

def parse_host_file(path):
    try:
        with open(path,"r") as f:
            hostdict = dict()
            for line in f:
                line_list = line.rstrip().split(" ")
                for entry in line_list[1:]:
                    hostdict[entry] = line_list[0]
        return hostdict
    except FileNotFoundError:
        print("Hostfile \"%s\" not found" % path)
        return false
    except:
        return false

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process input')
    parser.add_argument("--ip", help="set listen ip address", action="store", type=str, default="192.168.57.1")
    parser.add_argument("--port", help="set listen port", action="store", type=int, default=53)
    parser.add_argument("--withInternet", help="enable real resolving", action="store_true")
    parser.add_argument("--debug", help="enable debug logging", action="store_true")
    parser.add_argument("--hostFile", help="specify custom host file", action="store")
    args = parser.parse_args()

    if args.debug:
        print('IP: %s Port: %s withInternet: %s' % (args.ip, args.port, args.withInternet))

    if args.hostFile:
        print("Hostfile loaded")
        hostdict = parse_host_file(args.hostFile)

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((args.ip, args.port))

    try:
        while True:
            data, addr = udp_sock.recvfrom(1024)
            d = DNSRecord.parse(data)
            for question in d.questions:
                qdom = question.get_qname()
                r = d.reply()
                if qdom.idna() in hostdict:
                    r.add_answer(RR(qdom,rdata=A(hostdict[qdom.idna()]),ttl=60))
                    if args.debug:
                        print("\"%s\" in custom hostfile" % qdom.idna())
                        print("Request: %s --> %s" % (qdom.idna(), hostdict[qdom.idna()]))
                elif args.withInternet:
                    try:
                        realip = socket.gethostbyname(qdom.idna())
                    except Exception as e:
                        if args.debug:
                            print(e)
                        realip = args.ip
                    r.add_answer(RR(qdom,rdata=A(realip),ttl=60))
                    if args.debug:
                        print("Request: %s --> %s" % (qdom.idna(), realip))
                else:
                    r.add_answer(RR(qdom,rdata=A(args.ip),ttl=60))
                    if args.debug:
                        print("Request: %s --> %s" % (qdom.idna(), args.ip))
                udp_sock.sendto(r.pack(), addr)
    except KeyboardInterrupt:
        if args.debug:
            print("done.")
    udp_sock.close()
