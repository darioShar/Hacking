*** Setting up the server ***
# Folder :  dns_server #
Launch the little http server by specifying the port and max number of concurrent connections, e.g. :
$ sudo ./server 80 20





*** Launching the attach ***
# Folder : arp_spoofing_plus_dns_hijack #

First launch arp1.sh to setup arp spoofing, e.g. :
$ sudo ./arp1.sh

Then launch dns_hijack, e.g. :
$ sudo ./dns_hijack


