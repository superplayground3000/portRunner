from scapy.all import sniff

a=sniff(filter="tcp and ( port 27001 )",prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% seq: %TCP.seq% ack: %TCP.ack%"))