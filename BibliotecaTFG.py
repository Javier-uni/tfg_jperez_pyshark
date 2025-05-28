import pyshark
import logging
import os
import filecmp
import json
import re



# ──────────────────────────────── #
#  region FUNCIONES DE EXTRACCION  #
# ──────────────────────────────── #
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
    cap = pyshark.FileCapture(abspath, display_filter='icmp.type == 8')
    for pkt in cap:
        if hasattr(pkt, 'icmp'):
            if pkt.icmp.type == '8':  #Cuidado, 8 es un string
                if pkt.eth.src not in macs:
                    # print('MAC origen: '+pkt.eth.src)
                    macs.append(pkt.eth.src)
    logging.debug(macs)
    cap.close()
    if len(macs) == 0:
        logging.warning('No se ha encontrado la MAC de origen')
        return 0
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
    cap = pyshark.FileCapture(abspath, use_json=True)
    for pkt in cap:
        #no haria ni falta el hasttr
        if hasattr(pkt, 'frame_info'):
            if pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S') not in fecha:
                fecha.append(pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S'))  # comprobacion 2025

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
                    fecha.append(pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S'))  # comprobacion 2025

                if pkt.sniff_timestamp not in nanosegs:
                    nanosegs.append(pkt.sniff_timestamp)

    logging.debug(time)
    cap.close()
    return time

# endregion




# ──────────────────────────────── #
#  region FUNCIONES DE COMPROBACION  #
# ──────────────────────────────── #
def check_older(path_cap1, comprobacion):
    """
    Checks if the year in a Wireshark capture file matches the current year.

    Args:
        path_cap1 (str): The file path to the Wireshark capture file.
        comprobacion (object): An object with attributes 'year' and 'atrtime' that will be 
                              used to check and store the year validation result.

    Returns:
        None: Updates the comprobacion.atrtime attribute to False if the year doesn't match.
    """
    time = timestamps(path_cap1)
    if not str(comprobacion.year) in str(time[0]):
        comprobacion.atrtime = False
        logging.warning(f'La captura {path_cap1} NO tiene el año {comprobacion.year}')




def comprobacion_identica(path_cap1, path_cap2, comprobacion1, comprobacion2):
    """
    Checks if two capture files are exactly the same.
    This function compares two files specified by their paths and updates the 
    `comprobacion1` object based on whether the files are identical or not.

    Args:
        path_cap1 (str): The file path of the first capture.
        path_cap2 (str): The file path of the second capture.
        comprobacion1 (object): An object with an attribute `atrexact` that will be
                                set to False if the files are identical, and True otherwise.
        comprobacion2 (object): An object like comprobacion1
    Returns:
        None, updates the comprobacion1 and comprobacion2 objects.
    """
    #CUIDADO CON LOS PATHS

    abspath1 = os.path.abspath(path_cap1)
    abspath2 = os.path.abspath(path_cap2)
    if filecmp.cmp(abspath1, abspath2, shallow=False):
        logging.warning("Las capturas son idénticas: ")
        logging.warning('  Path 1: ' + str(path_cap1))
        logging.warning('  Path 2: ' + str(path_cap2))
        comprobacion1.atrexact = False
        comprobacion1.atrComprobacionIndividual = False
        comprobacion1.igual = os.path.basename(path_cap2)

        comprobacion2.atrexact = False
        comprobacion2.atrComprobacionIndividual = False
        comprobacion2.igual = os.path.basename(path_cap1)
    else:
        logging.debug("Las capturas no son identicas.")


def comprobaciondepaquetes(path_cap1, comprobacion):
    cap = pyshark.FileCapture(path_cap1)
    packet_count = sum(1 for _ in cap)
    if packet_count < 2:
        comprobacion.atrComprobacionIndividual = False
        logging.warning(f'La captura {path_cap1} NO tiene el numero de paquetes necesario')
    else:
        logging.info(f'La captura {path_cap1} tiene el numero de paquetes necesario')
    cap.close()


def num_captured_pckts(path_cap, comprobacion, numMin):
    """
    Checks if the cap has a minimun of packets.
    Args:
        cap_path (str): The file path to the capture file.
    Returns:
        True if the capture has more than 4 packets, False otherwise.
    """

    abspath = os.path.abspath(path_cap)
    cap = pyshark.FileCapture(abspath)
    numpaquetes = sum(1 for _ in cap)
    if numpaquetes >= numMin:
        logging.debug('La captura cuenta con un minimo de 4 paquetes' + str(numpaquetes))
        cap.close()
        suma = comprobacion.nota
        suma += 1
        comprobacion.nota = suma
        return True
    elif numpaquetes < numMin:
        logging.warning('La captura cuenta con unicamente ' + str(
            numpaquetes) + ' paquetes' + '-----------------------------------------------')
        cap.close()
        return False
    else:
        logging.critical(
            'Algo ha salido mal, hay un error en el analisis del numero de paquetes de la captura, min_packs')
        cap.close()


def num_vlan_captured_pckts(path_cap, comprobacion, numMin):
    """
    Checks if the cap has a minimun of packets with vlan id
    Args:
        cap_path (str): The file path to the capture file.
        comprobacion (object): An object with attributes, 'atrComprobacionIndividual'
        numMin (int): The minimum number of packets required (default = 4).
    Returns:
        None (changes the comprobacion object).
    """

    abspath = os.path.abspath(path_cap)
    cap = pyshark.FileCapture(abspath, display_filter='vlan')
    numpaquetes = sum(1 for _ in cap)
    cap.close()
    if numpaquetes >= numMin:
        logging.debug('La captura cuenta con un minimo de 4 paquetes VLAN' + str(numpaquetes))

    elif numpaquetes < numMin:
        logging.warning('La captura cuenta con unicamente ' + str(numpaquetes) + ' paquetes VLAN')
        comprobacion.atrComprobacionIndividual = False


    else:
        logging.critical('Algo ha salido mal, hay un error en el analisis del numero de paquetes de la captura, min_packs')


def min_macs_src(path_cap, comprobacion):
    print('EnProceso')


def check_arp_request_reply(path_cap1, comprobacion):
    """
    Checks if the ARP protocol is present in the capture file.
    Args:
        path_cap1 (str): The file path to the capture file.
        comprobacion (object): An object with attributes, 'atrComprobacionIndividual' 
    Returns:
        None (changes the comprobacion object)
    """

    abspath = os.path.abspath(path_cap1)
    cap = pyshark.FileCapture(abspath, display_filter='arp.opcode == 1')

    ARPRequest = sum(1 for _ in cap)
    cap.close()

    cap = pyshark.FileCapture(abspath, display_filter='arp.opcode == 2')
    ARPResponse = sum(1 for _ in cap)
    cap.close()

    if ARPRequest > 0 and ARPResponse > 0:
        logging.debug('La captura tiene peticiones y respuestas ARP')
        logging.debug('ARP Normal')

    elif ARPRequest == 0 and ARPResponse == 0:
        logging.info('La captura NO tiene peticiones ni respuestas ARP')
        logging.debug('ARP Normal, se ha capturado ping ya empezado')


    elif ARPRequest > 0 and ARPResponse == 0:
        #if ARPRequest == ARPResponse:
        logging.warning('La captura tiene peticiones ARP pero NO tiene respuestas')
        logging.warning('MAL, la captura no es normal')
        #Replantear si existen varias peticiones ARP sin respuesta
        comprobacion.atrComprobacionIndividual = False

    elif ARPRequest == 0 and ARPResponse > 0:
        logging.debug('La captura tiene respuestas ARP pero NO tiene peticiones')
        logging.debug('ARP Rarete, se ha capturado ping justo al hacer la peticion')
    else:
        logging.critical('Algo ha salido mal, hay un error en el analisis de la captura, comprobacionARP')


def check_ip_vlan(path_cap1, comprobacion):
    """
    Checks if the ICMP is coherent with the VLAN.
    Args:
        path_cap1 (str): The file path to the capture file.
        comprobacion (object): An object with attributes, 'atrComprobacionIndividual' will chance to True if the test is atrComprobacionIndividual.
    """

    abspath = os.path.abspath(path_cap1)
    ip = 0
    vlan = 0
    cap = pyshark.FileCapture(abspath, display_filter='icmp.type == 8')
    for pkt in cap:
        if hasattr(pkt, 'icmp'):
            if pkt.icmp.type == '8':
                logging.debug('La captura tiene peticiones ICMP echo request')
                logging.debug('ICMP Normal')
                ip = get_ip_id(pkt.ip.dst)
                if hasattr(pkt, 'vlan'):
                    vlan = pkt.vlan.id
                break
    cap.close()

    if ip == 0:
        logging.warning('La captura NO tiene peticiones ICMP echo request')
        logging.debug('ICMP Normal, se ha capturado ping ya empezado')
        comprobacion.atrComprobacionIndividual = False

    elif vlan == 0:
        logging.warning('La captura tiene peticiones ICMP echo request pero NO tiene el header de VLAN')
        comprobacion.atrComprobacionIndividual = False

    else:
        logging.debug('La captura tiene peticiones ICMP echo request y el header de VLAN')
        if ip != (vlan-3000):
            comprobacion.atrComprobacionIndividual = False
            logging.warning('La captura tiene peticiones ICMP echo request pero NO tiene el header de VLAN')
            logging.warning('Especial')

        elif comprobacion.atrComprobacionIndividual:
            logging.info('La captura ha pasado todos los tests, ✓')


def get_ip_id(ip_address):
    """
    Extracts the third octet from an IP address with format 10.220.XXX.1
    Args:
        ip_address (str): IP address string in format 10.220.XXX.1
    Returns:
        int: The XXX value (third octet) from the IP address
    """
    octets = ip_address.split('.')
    if len(octets) == 4 and octets[0] == '10' and octets[1] == '220' and octets[3] == '1':
        logging.debug('El IP es correcto')
        return int(octets[2])

    else:
        logging.warning('El formato IP no es correcto')
        return int(octets[2])



def check_vlan_802_1q(path_cap, comprobacion):
    numbers = re.findall(r'\d+', path_cap)
    logging.debug(f'Numbers extracted from path: {numbers}')

    # Load puestos.json file
    with open('puestos.json') as f:
        puestos = json.load(f)

    puesto = "puesto_"+str(numbers)
    #capt = os.path.basename(path_cap)
    abspath = os.path.abspath(path_cap)
    #expected_vlan = puestos[capt]["vlan"]
    expected_vlan = puestos[puesto]["vlan"]
    vlan = 0
    cap = pyshark.FileCapture(abspath, display_filter='icmp.type == 8')
    for pkt in cap:
        if hasattr(pkt, 'icmp'):
            if pkt.icmp.type == '8':
                logging.debug('La captura tiene peticiones ICMP echo request')
                logging.debug('ICMP Normal')
                if hasattr(pkt, 'vlan'):
                    vlan = pkt.vlan.id
                break
    cap.close()

    if vlan == 0:
        logging.warning('La captura tiene peticiones ICMP echo request pero NO tiene el header de VLAN')
        comprobacion.atrComprobacionIndividual = False

 


    else:
        logging.debug('La captura tiene peticiones ICMP echo request y el header de VLAN')
        if expected_vlan != vlan:
            comprobacion.atrComprobacionIndividual = False
            logging.warning('La captura tiene peticiones ICMP echo request pero NO tiene el header de VLAN')
            logging.warning('Especial')

        elif comprobacion.atrComprobacionIndividual:
            logging.info('La captura ha pasado todos los tests, ✓')
    
    
# endregion





# ──────────────────────────────── #
#  region FUNCIONES JSON  #
# ──────────────────────────────── #


def claseAdiccionarioCopiaExacta(comprobacion):
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'copia': comprobacion.atrexact,
        'igual': comprobacion.igual,
        'Comentario': 'La captura ' + str(comprobacion.name) + ' es una copia exacta de ' + str(
            comprobacion.igual) + '.'
    }
    return diccionario


def claseAdiccionarioCopia(comprobacion):
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'copia': comprobacion.atrComprobacionIndividual,
        'igual': comprobacion.igual,
        'Comentario': 'La captura ' + str(comprobacion.name) + ' es una copia de ' + str(comprobacion.igual) +
                      ' comparten mac origen y timestamp de las capturas.'
    }
    return diccionario


def claseAdiccionarioCopiaIndividual(comprobacion):
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'Passed': comprobacion.atrComprobacionIndividual,
        'igual': comprobacion.igual,
        'Comentario': 'Esta captura no ha pasado la comprobacion individual.'
    }
    return diccionario
# endregion
