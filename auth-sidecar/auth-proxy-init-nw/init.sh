#!/bin/bash
iptables -t nat -A PREROUTING -p tcp --dport 8000 -j REDIRECT --to-port 8080
iptables -t nat --list
