from scapy.all import sniff

def packet_callback(packet):
    #print packet summary
    print(packet.summary())

    #check for ip layer and extract information
    if packet.haslayer("IP"):
        ip_layer=packet["IP"]
        print(f"source ip: {ip_layer.src}, destination ip: {ip_layer.dst},protocol: {ip_layer.proto}")

    #check for tcp layer
    if packet.haslayer("TCP"):
        tcp_layer=packet["TCP"]
        print(f" source port:{tcp_layer.sport},destination ports:{tcp_layer.dport}")

    print("-"*50)

def main():
    #start sniffing packet
    print("start packet sniff")
    sniff(prn=packet_callback,filter="tcp",count=15)

if __name__=="__main__":

    main()