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


def comprobacionanual(path_cap1,comprobacion):
    time = timestamps(path_cap1)
    if not str(comprobacion.year) in str(time[0]):
        comprobacion.atrtime = False
        logging.warning(f'La captura {path_cap1} NO tiene el año {comprobacion.year}')
        
        
   
   
 ##comprobaciondepaquetes y minpacks...  
        
def comprobaciondepaquetes(path_cap1,comprobacion):
    cap = pyshark.FileCapture(path_cap1)
    packet_count = sum(1 for _ in cap)
    if packet_count < 2:
        comprobacion.passed = False
        logging.warning(f'La captura {path_cap1} NO tiene el numero de paquetes necesario')
    else:
        logging.info(f'La captura {path_cap1} tiene el numero de paquetes necesario')
    cap.close() 


def MinPacks(cap_path,comprobacion,numMin):
    """
    Checks if the cap has a minimun of packets.
    Args:
        cap_path (str): The file path to the capture file.
    Returns:
        True if the capture has more than 4 packets, False otherwise.
    """
    
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    numpaquetes = sum(1 for _ in cap)
    if numpaquetes >= numMin:
        logging.debug('La captura cuenta con un minimo de 4 paquetes' + str(numpaquetes) )
        cap.close()
        suma = comprobacion.nota
        suma += 1
        comprobacion.nota = suma
        return True
    elif numpaquetes < numMin:
        logging.warning('La captura cuenta con unicamente ' + str(numpaquetes ) + ' paquetes' + '-----------------------------------------------')
        cap.close()
        return False
    else:
        logging.critical('Algo ha salido mal, hay un error en el analisis del numero de paquetes de la captura, MinPacks')



def MinPacksVlan(cap_path,comprobacion,numMin):
    """
    Checks if the cap has a minimun of packets with vlan header?????????????????????????? MEJORAR REDACICON BURRO.
    Args:
        cap_path (str): The file path to the capture file.
    Returns:
        True if the capture has more than 4 packets, False otherwise.
    """
    
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath, display_filter='vlan')
    numpaquetes = sum(1 for _ in cap)
    if numpaquetes >= numMin:
        logging.debug('La captura cuenta con un minimo de 4 paquetes VLAN' + str(numpaquetes) )
        cap.close()
        suma = comprobacion.nota
        suma += 1
        comprobacion.nota = suma
        return True
    elif numpaquetes < numMin:
        logging.warning('La captura cuenta con unicamente ' + str(numpaquetes ) + ' paquetes VLAN')
        cap.close()
        return False
    else:
        logging.critical('Algo ha salido mal, hay un error en el analisis del numero de paquetes de la captura, MinPacks')

    
def MinMacsSrc(cap_patch,comprobacion):
    print('EnProceso')
    
