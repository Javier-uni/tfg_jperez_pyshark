## Prueba02
import pyshark
import os


os.system('cls')
print('Prueba 02 JP' + '')
#ojo con el path, poner r de RAW
#ojo con el path, absoluto y relativo
#abrimos el archivo
cap1 = pyshark.FileCapture(r"C:\Users\jpgja\Desktop\Random\uni\4.1\TFG\CapturasRed\p2-aptd9.pcapng")

#print(cap1[0])

#print ip
# TestIPsrc = cap1[0].ip.src
# print(TestIPsrc)

# TestIPdst = cap1[0].ip.dst
# print(TestIPdst)



TestVlanID = cap1[0].vlan.id
print(TestVlanID)


arrayVlan = []
for pkt in cap1:
    if hasattr(pkt,'vlan'):
        if pkt.vlan.id not in arrayVlan:
         arrayVlan.append(pkt.vlan.id)
         print('El Vlan ID es: '+pkt.vlan.id)


print(arrayVlan)


def IP():
 print(cap1)
 for pkt in cap1: 
  if hasattr(pkt, 'ip'):
   print(pkt.ip.src)
   print(pkt.ip.dst)
   print(pkt.ip.field_names)
IP()

def SHOW():
 cap1[0].show()
SHOW()

def ICMP():
 for pkt in cap1:
  if hasattr(pkt, 'icmp'):
   print(pkt.icmp.type)
   print(pkt.icmp.code)
   print(pkt.icmp.field_names)
ICMP()



cap1.close()