import socket


HOST = '192.168.56.103'
PORT = 46221

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

msg = '<p>Clément et Dario</p><img src="https://www.cnet.com/a/img/2ZjmzrycBZQD9Dpnt_EnfQ7TTro=/940x0/2020/05/31/5112f3db-5af6-431c-bc0d-a8108ccad2ee/spacex-falcon-9-launch.jpg" />'
# msg = ''
sock.send(msg.encode())