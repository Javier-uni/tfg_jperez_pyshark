import pyshark
import logging
import os
import filecmp
import json
import re
import json
import csv



# ──────────────────────────────── #
#  region FUNCIONES DE EXTRACCION  #
# ──────────────────────────────── #
    # def resultadomacs(cap_path):
#     """
#     Extracts and returns a list of unique source MAC addresses from a Wireshark capture file.
#     Args:
#         cap_path (str): The file path to the Wireshark capture file.
#     Returns:
#         list: A list of unique source MAC addresses found in the capture file.
#     """

#     macs = []
#     abspath = os.path.abspath(cap_path)
#     cap = pyshark.FileCapture(abspath)
#     for pkt in cap:
#         if hasattr(pkt, 'eth'):
#             if pkt.eth.src not in macs:
#                 macs.append(pkt.eth.src)
#     logging.debug(macs)
#     cap.close()
#     return macs


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

def comparacionTemporal(path_cap1, path_cap2, comprobacion1, comprobacion2):
    """
    Compare timestamps between two network captures to detect potential fraud.
    
    This function is triggered when two captures have the same MAC source address.
    Due to the laws of physics, if both captures also have identical timestamps,
    they are considered fraudulent since the same device cannot be in two places
    at once.

    Args:
        path_cap1 (str): File path to the first capture file
        path_cap2 (str): File path to the second capture file  
        comprobacion1 (Comprobacion): Comprobacion object for first capture, updated if fraud detected
        comprobacion2 (Comprobacion): Comprobacion object for second capture, updated if fraud detected

    The function marks captures as fraudulent by setting atrtime=False and 
    atrComprobacionIndividual=False in their respective Comprobacion objects if:
    - They have exactly matching timestamps
    - They have any packets with matching timestamps
    """
    time1 = timestamp(path_cap1)
    time2 = timestamp(path_cap2)
    sigue = False
    if time1 == time2:
        logging.warning('Las capturas tienen exactamente los mismos tiempos de captura')
        comprobacion1.atrtime = False
        comprobacion1.igual= os.path.basename(path_cap2)
        comprobacion1.atrComprobacionGlobal = False

        comprobacion2.atrtime = False
        comprobacion2.igual= os.path.basename(path_cap1)
        comprobacion2.atrComprobacionGlobal = False

    else:
        for i in range(len(time1[0])):
            for j in range(len(time2[0])):
                if (time1[0][i] == time2[0][j]) and not sigue:
                    if time1[1][i] == time2[1][j]:
                        sigue = True
                        logging.warning('Las capturas tienen los mismos tiempos de captura('+comprobacion1.name+'y'+comprobacion2.name+')')
                        comprobacion1.atrtime = False
                        comprobacion1.atrComprobacionGlobal = False
                        comprobacion1.igual = os.path.basename(path_cap2)

                        comprobacion2.atrtime = False
                        comprobacion2.atrComprobacionGlobal = False
                        comprobacion2.igual = os.path.basename(path_cap1)
                        break


def dict_csv(path_cap):
    """
    Extracts the puesto identifier from the given path, reads the 'puestos.csv' file,
    and returns a dictionary mapping puesto numbers to their expected VLAN values.
    The function expects the 'puestos.csv' file to be in the current working directory,
    with at least four columns per row. It skips the header and any empty lines, and
    cleans each field by stripping spaces and quotes. The puesto identifier is extracted
    from the first sequence of digits found in the 'path_cap' string.
    Args:
        path_cap (str): The file path containing the puesto identifier (e.g., 'g12_aptd3.pcap').
    Returns:
        dict: A dictionary where each key is a puesto number (as a string) and each value
              is the corresponding expected VLAN (as an integer), i.e.,
              puestos_dict[puesto_num] = expected_vlan.
    Raises:
        Logs errors if the puesto identifier is not found in the CSV or if the VLAN value
        is invalid. Returns False in these error cases.
    """
    
    
    numbers = re.findall(r'\d+', path_cap)
    logging.debug(f'Numbers extracted from path: {numbers}')
   # Tomar el primer número como identificador del puesto
   # Formato esperado: gXY_aptdZ.pcap
    puesto_id = numbers[0]  # Mantener como string

    # Cargar y procesar puestos.csv
    puestos_dict = {}
    with open('puestos.csv', 'r', newline='', encoding='utf-8') as csvfile:
        # Leer archivo CSV ignorando espacios y caracteres especiales
        reader = csv.reader(csvfile, skipinitialspace=True)
        
        # Saltar encabezados (primera línea)
        next(reader)
        
        for row in reader:
            # Filtrar filas vacías en caso de que haya líneas en blanco
            if not row:
                continue
                
            # Limpiar cada campo: quitar comillas y espacios
            cleaned_row = [field.strip().strip('"') for field in row if field.strip()]
            
            # Verificar que tenga suficientes columnas
            if len(cleaned_row) >= 4:
                puesto_num = cleaned_row[0]
                vlan_value = cleaned_row[3]
                
                # Almacenar en diccionario
                puestos_dict[puesto_num] = vlan_value

    # Buscar la VLAN correspondiente
    if puesto_id not in puestos_dict:
        logging.error(f"Puesto {puesto_id} no encontrado en puestos.csv")
        return False

    expected_vlan = puestos_dict[puesto_id]
    
    try:
        # Convertir VLAN a entero si es necesario
        expected_vlan = int(expected_vlan)
    except ValueError:
        logging.error(f"Valor de VLAN inválido para puesto {puesto_id}: {expected_vlan}")
        return False
    
    return puestos_dict


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


def comprobaciondepaquetes(cap_path, comprobacion):
    """
    Checks if the capture file has a minimum number of packets.

    Args:
        cap_path (str): The file path of the capture
        comprobacion (object): An object with an attribute `atrComprobacionIndividual` that will be
                                set to False if the files are identical, and True otherwise.
    Returns:
        None, updates the comprobacion object.
    """
    cap = pyshark.FileCapture(cap_path)
    packet_count = sum(1 for _ in cap)
    if packet_count < 2:
        comprobacion.atrComprobacionIndividual = False
        logging.warning(f'La captura {cap_path} NO tiene el numero de paquetes necesario')
    else:
        logging.info(f'La captura {cap_path} tiene el numero de paquetes necesario')
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


def min_icmp_captured_pckts(path_cap, comprobacion,numMin=4):
    """
    Checks if the capture has a minimum number of ICMP packets.
    Args:
        path_cap (str): The file path to the capture file.
        comprobacion (object): An object with attributes, 'atrComprobacionIndividual'
    Returns:
        None (changes the comprobacion object).
    """
    abspath = os.path.abspath(path_cap)
    cap = pyshark.FileCapture(abspath, display_filter='icmp.type == 8')#REVISAR SI SE PUEDE HACER CON ICMP
    numpaquetes = sum(1 for _ in cap)
    cap.close()
    if numpaquetes >= numMin:
        logging.debug('La captura cuenta con un minimo de ' + str(numMin) + ' paquetes ping, correspondiente con el ping -c ' + str(numMin))
    elif numpaquetes < numMin:
        logging.warning('La captura cuenta con unicamente ' + str(numpaquetes) + ' paquetes ICMP')
        comprobacion.atrComprobacionIndividual = False
    else:
        logging.critical('Algo ha salido mal, hay un error en el analisis del numero de paquetes de la captura, min_packs')


def check_arp_request_reply(path_cap1, comprobacion):
    """
    Checks the ARP requests and responses in the capture file
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


def check_ip_vlan(path_cap, comprobacion):
    """
    Checks if the IP is coherent with the expected VLAN.
    Important: This uses the puestos.json file to check the expected VLAN for the given capture.
    Args:
        path_cap (str): The file path to the capture file.
        comprobacion (object): An object with attributes, 'atrComprobacionIndividual' will chance to True if the test is atrComprobacionIndividual.
    """

    numbers = re.findall(r'\d+', path_cap)
    logging.debug(f'Numbers extracted from path: {numbers}')
   # Tomar el primer número como identificador del puesto
   # Formato esperado: gXY_aptdZ.pcap
    puesto_id = numbers[0]  # Mantener como string

    # Cargar y procesar puestos.csv
    puestos_dict = {}
    with open('puestos.csv', 'r', newline='', encoding='utf-8') as csvfile:
        # Leer archivo CSV ignorando espacios y caracteres especiales
        reader = csv.reader(csvfile, skipinitialspace=True)
        
        # Saltar encabezados (primera línea)
        next(reader)
        
        for row in reader:
            # Filtrar filas vacías en caso de que haya líneas en blanco
            if not row:
                continue
                
            # Limpiar cada campo: quitar comillas y espacios
            cleaned_row = [field.strip().strip('"') for field in row if field.strip()]
            
            # Verificar que tenga suficientes columnas
            if len(cleaned_row) >= 4:
                puesto_num = cleaned_row[0]
                vlan_value = cleaned_row[3]
                
                # Almacenar en diccionario
                puestos_dict[puesto_num] = vlan_value

    # Buscar la VLAN correspondiente
    if puesto_id not in puestos_dict:
        logging.error(f"Puesto {puesto_id} no encontrado en puestos.csv")
        return False

    expected_vlan = puestos_dict[puesto_id]
    
    try:
        # Convertir VLAN a entero si es necesario
        expected_vlan = int(expected_vlan)
    except ValueError:
        logging.error(f"Valor de VLAN inválido para puesto {puesto_id}: {expected_vlan}")
        return False

    logging.debug(f'Expected VLAN for puesto {puesto_id}: {expected_vlan}')


    abspath = os.path.abspath(path_cap)
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
    """
    8021Q cojo mensaje buscando cabecera8021q buscando vlanid para comprobar con puesto
    Checks if the ICMP is coherent with the expected VLAN.
    Important: This uses the puestos.json file to check the expected VLAN for the given capture.
    Args:
        path_cap (str): Path to the capture file to be analyzed.

        comprobacion (object): An object used to record the result of the VLAN check.

    """

    numbers = re.findall(r'\d+', path_cap)
    logging.debug(f'Numbers extracted from path: {numbers}')
    if not numbers:
        logging.error('No se han encontrado números en el nombre del fichero de captura')
        logging.error('Posiblemente el nombre del fichero no tiene un formato correcto')

   # Tomar el primer número como identificador del puesto
   # Formato esperado: gXY_aptdZ.pcap
    puesto_id = numbers[0]  # Mantener como string

    # Cargar y procesar puestos.csv
    puestos_dict = {}
    with open('puestos.csv', 'r', newline='', encoding='utf-8') as csvfile:
        # Leer archivo CSV ignorando espacios y caracteres especiales
        reader = csv.reader(csvfile, skipinitialspace=True)
        
        # Saltar encabezados (primera línea)
        next(reader)
        
        for row in reader:
            # Filtrar filas vacías en caso de que haya líneas en blanco
            if not row:
                continue
                
            # Limpiar cada campo: quitar comillas y espacios
            cleaned_row = [field.strip().strip('"') for field in row if field.strip()]
            
            # Verificar que tenga suficientes columnas
            if len(cleaned_row) >= 4:
                puesto_num = cleaned_row[0]
                vlan_value = cleaned_row[3]
                
                # Almacenar en diccionario
                puestos_dict[puesto_num] = vlan_value

    # Buscar la VLAN correspondiente
    if puesto_id not in puestos_dict:
        logging.error(f"Puesto {puesto_id} no encontrado en puestos.csv")
        return False

    expected_vlan = puestos_dict[puesto_id]
    
    try:
        # Convertir VLAN a entero si es necesario
        expected_vlan = int(expected_vlan)
    except ValueError:
        logging.error(f"Valor de VLAN inválido para puesto {puesto_id}: {expected_vlan}")
        return False


    abspath = os.path.abspath(path_cap)
    ip = 0
    cap = pyshark.FileCapture(abspath, display_filter='icmp.type == 8')
    for pkt in cap:
        if hasattr(pkt, 'icmp'):
            if pkt.icmp.type == '8':
                logging.debug('La captura tiene peticiones ICMP echo request')
                logging.debug('ICMP Normal')
                ip = get_ip_id(pkt.ip.dst)
                break
    cap.close()

    if ip == 0:
        logging.warning('La captura NO tiene peticiones ICMP echo request')
        logging.debug('ICMP Normal, se ha capturado ping ya empezado')
        comprobacion.atrComprobacionIndividual = False

    elif expected_vlan == 0:
        logging.warning('La captura tiene peticiones ICMP echo request pero NO tiene el header de VLAN')
        comprobacion.atrComprobacionIndividual = False

    else:
        logging.debug('La captura tiene peticiones ICMP echo request y el header de VLAN')
        if ip != (expected_vlan-3000):
            comprobacion.atrComprobacionIndividual = False
            logging.warning('La captura tiene peticiones ICMP echo request pero NO tiene el header de VLAN')
            logging.warning('Especial')

        elif comprobacion.atrComprobacionIndividual:
            logging.info('La captura ha pasado todos los tests, ✓')


# endregion





# ──────────────────────────────── #
#  region FUNCIONES DE INFORME  #
# ──────────────────────────────── #


def claseAdiccionarioCopiaExacta(comprobacion):
    """
    Converts a comprobacion object representing an exact copy case into a dictionary.
    This function extracts relevant attributes from the comprobacion object and formats them
    into a dictionary structure, which is useful for further processing such as PDF generation.
    Args:
        comprobacion: An object containing the attributes 'name', 'atrmac', 'atrexact', and 'igual'.
            - name: The name or identifier of the capture.
            - atrmac: The MAC attribute associated with the capture.
            - atrexact: The attribute indicating the exact copy.
            - igual: The reference to the original capture that is being copied.
    Returns:
        dict: A dictionary containing the extracted data and a formatted comment describing
        the exact copy relationship, suitable for export or transformation to PDF.
    """
    
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
    """
    Converts a comprobacion object representing a general copy case into a dictionary with relevant attributes.
    Args:
        comprobacion: An object containing the following attributes:
            - name: The name or identifier of the capture.
            - atrmac: The MAC address associated with the capture.
            - atrComprobacionIndividual: Attribute indicating the copy status or related information.
            - igual: The identifier of the capture that is considered equal (the original).
    Returns:
        dict: A dictionary with the following keys:
            - 'nombre': The name of the capture.
            - 'atrmac': The MAC address of the capture.
            - 'copia': The copy status or related information.
            - 'igual': The identifier of the original capture.
            - 'Comentario': A descriptive comment explaining that the capture is a copy, sharing MAC address and timestamp with the original.
    """
    
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
    """
    Converts a failed individual test result (comprobacion) into a dictionary representation.
    This function is used when a capture does not pass individual verification tests.
    It extracts relevant attributes from the `comprobacion` object and returns them in a dictionary,
    including a fixed comment indicating the failure.
    Args:
        comprobacion: An object representing the result of an individual test, expected to have
            the attributes `name`, `atrmac`, `atrComprobacionIndividual`, and `igual`.
    Returns:
        dict: A dictionary containing the following keys:
            - 'nombre': The name of the capture.
            - 'atrmac': The MAC attribute of the capture.
            - 'Passed': The result of the individual verification.
            - 'igual': Whether the capture matches the expected result.
            - 'Comentario': A fixed comment indicating the capture did not pass the individual test.
    """
    
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'Passed': comprobacion.atrComprobacionIndividual,
        'igual': comprobacion.igual,
        'Comentario': 'Esta captura no ha pasado la comprobacion individual.'
    }
    return diccionario
# endregion
