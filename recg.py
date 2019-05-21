import struct

def decode_PcapFileHeader(B_datastring):


    header = {}
    header['magic_number'] = B_datastring[0:4]
    header['version_major'] = B_datastring[4:6]
    header['version_minor'] = B_datastring[6:8]
    header['thiszone'] = B_datastring[8:12]
    header['sigfigs'] = B_datastring[12:16]
    header['snaplen'] = B_datastring[16:20]
    header['linktype'] = B_datastring[20:24]
    return header


def decode_PcapDataPacket(B_datastring):
    packet_num = 0
    packet_data = []
    header = {}
    #data = ''
    i = 24
    while(i+16<len(B_datastring)):
       
       #header['GMTtime'] = B_datastring[i:i+4]
       #header['MicroTime'] = B_datastring[i+4:i+8]
       #header['CapLen'] = B_datastring[i+8:i+12]
       #header['Len'] = B_datastring[i+12:i+16]
       
       # the len of this packet
       header = B_datastring[i:i+16]
       packet_len = struct.unpack('I', B_datastring[i+8:i+12])[0]
       if (i+16+packet_len > len(B_datastring)):
           break
       # the data of this packet
       data = B_datastring[i+16:i+16+packet_len]
      
       # save this packet data
       packet_data.append((header,data))
 
       i = i + packet_len + 16
       packet_num += 1
          
    return packet_data



def read_Pcap(fileName):
    filepcap = open(fileName,'rb')
    string_data = filepcap.read()
    #print(string_data)
    packet_data = decode_PcapDataPacket(string_data)
    
    return packet_data






def is_cip_en(data):
    if len(data) < 44:
        return False
    startbit=42
    item_count=struct.unpack("<I",data[42:44]+bytes([0,0]))[0]
    item_start=44
    
    for item_num in range(item_count):
        if len(data[item_start:])<2:
            return False
        item_length=struct.unpack("<I",data[item_start+2:item_start+4]+bytes([0,0]))[0]

        if len(data[item_start+4:])<item_length:
            return False
        item_start=item_start+2+2+item_length
    return True



packet_data=read_Pcap("idel.pcap")

for one_packet in packet_data:
    print(len(one_packet[1]));
    print(is_cip_en(one_packet[1]));
