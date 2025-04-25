import pyshark
import logging
import os







##Analisis con wireshark
def resultadomacs(cap_path):
    """
    Extracts and returns a list of unique source MAC addresses from a Wireshark capture file.
    Args:
        cap_path (str): The file path to the Wireshark capture file.
    Returns:
        list: A list of unique source MAC addresses found in the capture file.
    """
    
    macs = []
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    for pkt in cap:
        if hasattr(pkt, 'eth'):
            if pkt.eth.src not in macs:
             macs.append(pkt.eth.src)
    logging.debug(macs)
    cap.close()
    return macs


def resultadomacsrc(cap_path):
    """
    Extracts and returns the MAC address of the host pc from a Wireshark capture file.
    Args:
        cap_path (str): The file path to the Wireshark capture file.
    Returns:
        list: It should return the MAC address of the host pc.
    """
    
    macs = []
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    for pkt in cap:
        if hasattr(pkt, 'icmp'):
            if pkt.icmp.type == '8':#Cuidado, 8 es un string
                if pkt.eth.src not in macs:
                    # print('MAC origen: '+pkt.eth.src)
                    macs.append(pkt.eth.src)
    logging.debug(macs)
    cap.close()
    return macs



def vid(cap_path):
    vids = []
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    for pkt in cap:
        if hasattr(pkt, 'vlan'):
            if pkt.vlan.id not in vids:
             vids.append(pkt.vlan.id)
    logging.debug(vids)
    cap.close()
    return vids


def timestamps(cap_path):
    """
    Extracts and returns all the timestamps from the specified capture file.
    Args:
        cap_path (str): The file path to the capture file.
    Returns:
        list: A list containing two lists:
            - The first list contains timestamps in the format [day, month, year, hour, minute, second].
            - The second list contains timestamps in nanoseconds.
    """
    
    fecha = []
    nanosegs = []
    times = [fecha, nanosegs]
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    for pkt in cap:
        #no haria ni falta el hasttr
        if hasattr(pkt, 'frame_info'):
            if pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S') not in fecha:
             fecha.append(pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S')) # comprobacion 2025
             
            if pkt.sniff_timestamp not in nanosegs:
             nanosegs.append(pkt.sniff_timestamp)
            
    logging.debug(times)
    cap.close()
    return times


def timestamp(cap_path):
    """
    Extracts and returns the ICMP echo request timestamps from the specified capture file.
    Args:
        cap_path (str): The file path to the capture file.
    Returns:
        list: A list containing two lists:
            - The first list contains timestamps in the format [day, month, year, hour, minute, second].
            - The second list contains timestamps in nanoseconds.
    """
        
    fecha = []
    nanosegs = []
    time = [fecha, nanosegs]
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    for pkt in cap:
        #no haria ni falta el hasttr
        if hasattr(pkt, 'icmp'):
            if pkt.icmp.type == '8':
             if pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S') not in fecha:
              fecha.append(pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S')) # comprobacion 2025
             
             if pkt.sniff_timestamp not in nanosegs:
              nanosegs.append(pkt.sniff_timestamp)
            
    logging.debug(time)
    cap.close()
    return time


def MinPacks(cap_path,comprobacion):
    """
    Checks if the cap has a minimun of packetss.
    Args:
        cap_path (str): The file path to the capture file.
    Returns:
        True if the capture has more than 4 packets, False otherwise.
    """
    
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    minpaquetes = len(cap)
    if minpaquetes > 4:
        logging.debug('La captura cuenta con un minimo de 4 paquetes' + str(minpaquetes) )
        cap.close()
        suma = comprobacion.nota
        suma += 1
        comprobacion.nota = suma
        return True
    elif minpaquetes < 5:
        logging.warning('La captura cuenta con unicamente' + minpaquetes )
        cap.close()
        return False
    else:
        logging.critical('Algo ha salido mal, hay un error en el analisis del numero de paquetes de la captura')



def MinPacksVlan(cap_path,comprobacion):
    print('EnProceso')
    
def MinMacsSrc(cap_patch,comprobacion):
    print('EnProceso')
    
