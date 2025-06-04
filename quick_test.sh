#! /bin/bash
# target is scanme.nmap.org
#https://whatismyipaddress.com/ip/45.33.32.156  
python3 portRunner.py \
  --ip "45.33.32.156" \
  --port "22" \
  --worker 1 --pps 50
