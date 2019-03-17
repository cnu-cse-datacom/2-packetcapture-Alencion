import socket
import struct


def parsing_ethernet_header(data):
  ethernet_header = struct.unpack("!6c6c2s", data)
  ether_src = convert_ethernet_address(ethernet_header[0:6])
  ether_dest = convert_ethernet_address(ethernet_header[6:12])
  ip_header = "0x"+ethernet_header[12].hex()

  print("======ethernet_header======")
  print("src_mac_address:", ether_src)
  print("dest_mac_address:", ether_dest)
  print("ip_version", ip_header)

def parsing_ip_header(data):
  ip_header = struct.unpack("!1B1B1H1H1H1B1B1H4B4B",data)
  ip_version = ip_header[0] >> 4
  ip_Length = ip_header[0] & 13
  differentiated_service_codepoint = ip_header[1] >> 4
  explicit_congestion_notification = ip_header[1] & 13
  total_legnth = ip_header[2]
  identification = hex(ip_header[3])
  flags = hex(ip_header[4])
  reserved_bit = ip_header[4] >> 15 & 1
  not_fragments = ip_header[4] >> 14 & 1
  fragments = ip_header[4] >> 13 & 1
  fragments_offset = ip_header[4] >> 12 & 1
  time_to_live = ip_header[5]
  protocal = format(ip_header[6],'x')
  header_checksum = hex(ip_header[7])
  sorce_ip_address = convert_ip_address(ip_header[8:12])
  dest_ip_address = convert_ip_address(ip_header[12:16])

  print("======ip_header======")
  print("ip_version:",ip_version)
  print("ip_Length:",ip_Length)
  print("differentiated_service_codepoint:", differentiated_service_codepoint)
  print("explicit_congestion_notification:", explicit_congestion_notification)
  print("total_legnth:",total_legnth)
  print("identification:", identification)
  print("flags:",flags)
  print(">>>reserved_bit:", reserved_bit)
  print(">>>not_fragments:", not_fragments)
  print(">>>fragments:", fragments)
  print(">>>fragments_offset:", fragments_offset)
  print("Time to live:", time_to_live)
  print("protocol:", protocal)
  print("header checksum:", header_checksum)
  print("sorce_ip_address:", sorce_ip_address)
  print("dest_ip_address:", dest_ip_address)
  
  return protocal

def parsing_tcp_header(data):
  tcp_header = struct.unpack("!1H1H1I1I1H1H1H1H",data[0:20])
  src_port = tcp_header[0]
  dec_port = tcp_header[1]
  seq_num = tcp_header[2]
  ack_num = tcp_header[3]
  header_len = tcp_header[4] >> 12
  flags = tcp_header[4] & 8191
  reserved = tcp_header[4] >> 9 & 7
  nonce = tcp_header[4] >> 8 & 1
  cwr = tcp_header[4] >> 7 & 1
  urgent = tcp_header[4] >> 5 & 1
  ack = tcp_header[4] >> 4 & 1
  push = tcp_header[4] >> 3 & 1
  reset = tcp_header[4] >> 2 & 1
  syn = tcp_header[4] >> 1 & 1
  fin = tcp_header[4] & 1
  window_size_value = tcp_header[5]
  checksum = tcp_header[6]
  urgent_pointer = tcp_header[7]

  print("======tcp_header======")
  print("src_port:", src_port)
  print("dec_port:", dec_port)
  print("seq_num:", seq_num)
  print("ack_num:", ack_num)
  print("header_len:", header_len)
  print("flags:", flags)
  print(">>>reserved:", reserved)
  print(">>>nonce:", nonce)
  print(">>>cwr:", cwr)
  print(">>>urgent:", urgent)
  print(">>>ack:", ack)
  print(">>>push:", push)
  print(">>>reset:", reset)
  print(">>>syn:", syn)
  print(">>>fin:", fin)
  print("window_size_value:", window_size_value)
  print("checksum:",checksum)
  print("urgent_pointer:",urgent_pointer)

def parsing_udp_header(data):
  udp_header = struct.unpack("!1H1H1H1H",data)
  src_port = udp_header[0]
  dst_port = udp_header[1]
  leng = udp_header[2]
  header_cheksum = hex(udp_header[3])

  print("======udp_header======")
  print("src_port:", src_port)
  print("dst_port:", dst_port)
  print("leng:", leng)
  print("header_cheksum:", header_cheksum)

def convert_ethernet_address(data):
  ethernet_addr = list()
  for i in data:
    ethernet_addr.append(i.hex())
  ethernet_addr = ":".join(ethernet_addr)
  return ethernet_addr

def convert_ip_address(data):
  ip_addr = list()
  for i in data:
    ip_addr.append(str(i))
  ip_addr = '.'.join(ip_addr)
  return ip_addr

recv_socket=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0X0800))

while True:
  data = recv_socket.recvfrom(20000)
  parsing_ethernet_header(data[0][0:14])
  protocal = parsing_ip_header(data[0][14:34])
  if protocal == '11':
    parsing_udp_header(data[0][34:42])
  elif protocal == '6':
    parsing_tcp_header(data[0][34:])
  
