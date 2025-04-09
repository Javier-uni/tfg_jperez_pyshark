import logging
import os
import pyshark
import filecmp
import json



def main():
    
    print("EJecutando el programa")
    logconfig()
    directorio='capturas03'
    dir(directorio)
    # recorrerDirectorio(directorio)
    recorrerDirectorioFinal(directorio)
    
    
    
    
    
def logconfig():
 """
 Configures the logging module to display log messages with a level of INFO or higher.
 The log messages will be formatted to show the log level and the message content.
 """
 logging.basicConfig(
 #level = logging.DEBUG, # Todos los mensajes de log
  level=logging.INFO, # Solo mensajes de INFO en adelante
  format='%(levelname)s: %(message)s'
    )

def logexmpl():
 """
 Example of how to use the logging module.
 """
 logging.debug("Este mensaje no aparecerá porque el nivel es INFO.")
 logging.info("Este mensaje SÍ se mostrará.")
 logging.warning("Mensaje de warning.")
 logging.error("Mensaje de error.")
 logging.critical("Mensaje crítico.")   

    

class Comprobacion:
    """
    A class used to represent a Comprobacion (Verification).
    Attributes
    ----------
    name : str
        The name of the capture.
        
    atrmac : bool, optional
        A boolean attribute (default is True) Turns to False if the srcMac appears in another capture.
        
    atrtime : bool, optional
        A boolean attribute (default is True) Turns to False if either .
        
    year : str, optional
        The year associated with the capture (default is '2025').
        
    copia : bool, optional
        A boolean attribute indicating if there has been a copy (default is True).
        
    atrexact : bool, optional
        A boolean attribute indicating if there has been an exact copy(default is True).
        
    igual : str, optional
        A string attribute that points the name of the copied capture (default is an empty string).
        
    passed : bool, optional
        A boolean attribute indicating if the verification passed (default is True).
        
    Methods
    -------
    __init__(self, name, atrmac=True, atrtime=True, year='2025', copia=True, atrexact=True, igual='', passed=True)
        Initializes the Comprobacion class with the provided attributes.
    """
    
    def __init__(self, name,atrmac=True, atrtime=True,year='2025', 
                  copia=True, atrexact=True, igual='',passed=True):
        self.name = name 
        self.atrmac = atrmac
        self.atrtime = atrtime
        self.year = year
        self.copia = copia 
        self.atrexact = atrexact
        self.igual = igual
        self.passed = passed #Incluye comprobacion unica y a pares
        
          
def dir(directorio):
    """
    Checks if a directory exists, and if not, creates it.
    Args: 
        directorio (str): The name of the directory to check or create.
    If the directory does not exist, it will be created. If it already exists, a message will be printed indicating that the directory already exists.
    """   
    if not os.path.exists(str(directorio)):
        logging.warning('El directorio '+str(directorio)+' no existe, creando...')
        os.mkdir(str(directorio))
    else:
        logging.debug('El directorio '+str(directorio)+' ya existe :)')
 
 
 
# recorrerDirectorio y recorrercapturas son =        
def recorrerDirectorio(directorio):
    print('El directorio tiene '+str(len(os.listdir(directorio)))+' capturas')
    for filename in os.listdir(directorio):
        cap_path = os.path.join(directorio, filename)
        if os.path.isfile(cap_path):
            print('Analizando captura: ' + cap_path)
            # resultadomacs(cap_path)
            # vid(cap_path)
            # timestamp(cap_path)
            timestamp(cap_path)
            

def recorrerCapturas(directorio):
    print('El directorio tiene '+str(len(os.listdir(directorio)))+' capturas')
    archivos = [] 
    for filename in os.listdir(directorio):
        archivos.append(str(directorio+'/'+filename))
    for archivo in archivos:
        print('Analizando captura: ' + archivo)
        resultadomacsrc(archivo)
        
def recorrerDirectorioFinal(directorio):
    #EFICIENTEEEEEEEEEEEE
    logging.info('El directorio tiene '+str(len(os.listdir(directorio)))+' capturas')
    archivos = []
    comprobaciones = []
    for filename in os.listdir(directorio):
        archivos.append(str(directorio+'/'+filename))
        comprobacion = Comprobacion(filename)
        comprobaciones.append(comprobacion)
    logging.debug(archivos)
    logging.debug(len(archivos)) 
    for i in range(len(archivos)):
        comprobacionanual(archivos[i],comprobaciones[i])
        for j in range(i, len(archivos)):
            if i != j:#curioso, podemos quitar esta comprobacion si en range ponemos (i+1, len(archivos))
             analizar_capturas(archivos[i], archivos[j],comprobaciones[i])
         
    exponerResultados(comprobaciones)   


       





def comprobacionIdentica(path_cap1, path_cap2, comprobacion1):
    """
    Checks if two capture files are exactly the same.
    This function compares two files specified by their paths and updates the 
    `comprobacion1` object based on whether the files are identical or not.
    Parameters:
    path_cap1 (str): The file path of the first capture.
    path_cap2 (str): The file path of the second capture.
    comprobacion1 (object): An object with an attribute `atrexact` that will be 
                            set to False if the files are identical, and True otherwise.
    Returns:
    None
    """
    #CUIDADO CON LOS PATHS
    
    abspath1 = os.path.abspath(path_cap1)
    abspath2 = os.path.abspath(path_cap2)
    if filecmp.cmp(abspath1, abspath2, shallow=False):
        print("Las capturas son idénticas: ")
        print('  Path 1: '+ str(path_cap1))
        print('  Path 2: '+ str(path_cap2))
        comprobacion1.atrexact = False
    else:
        logging.debug("Las capturas no son identicas.")
        comprobacion1.atrexact = True #MAL Lo podre quitar mas adelante
        
        
def analizar_capturas(path_cap1, path_cap2,comprobacion):      
    # Aquí puedes agregar el análisis que desees realizar con las capturas
    logging.info(f"Analizando {path_cap1} y {path_cap2}")
    comprobacionIdentica(path_cap1, path_cap2, comprobacion)
    if  comprobacion.atrexact:
     mac1 = resultadomacsrc(path_cap1)
     mac2 = resultadomacsrc(path_cap2)
     if mac1 == mac2:
        comprobacion.atrmac = False
        comprobaciontemporal(path_cap1, path_cap2,comprobacion)
        
        
        
def exponerResultados(comprobaciones):
    logging.debug('Exponiendo resultados')
    listado_diccionarios = []
    with open('resultados.json', 'w') as file:
     for comprobacion in comprobaciones:
        logging.debug('Analizando captura: '+comprobacion.name)
        if not comprobacion.atrexact:
            logging.debug(f'La captura {comprobacion.name}  es una copia exacta')
            diccionario = claseAdiccionarioCopiaExacta(comprobacion)
            listado_diccionarios.append(diccionario)
        else:
            if not comprobacion.copia:
             logging.debug(f'La captura {comprobacion.name}  es una copia')
             diccionario = claseAdiccionarioCopia(comprobacion)
             listado_diccionarios.append(diccionario)
            else:
             if not comprobacion.passed:
                logging.debug(f'La captura {comprobacion.name}  no ha pasado la comprobacion')
                diccionario = claseAdiccionarioCopiaIndividual(comprobacion)
                listado_diccionarios.append(diccionario)
     json.dump(listado_diccionarios, file, indent=4)
         
             
        
        
        


def claseAdiccionarioCopiaExacta(comprobacion):
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'copia': comprobacion.atrexact,
        'Comentario': 'Esta captura es una copia exacta de:'+ comprobacion.igual   
    }
    return diccionario


def claseAdiccionarioCopia(comprobacion):
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'copia': comprobacion.copia,
        'Comentario': 'Esta captura es una copia de: '+ comprobacion.igual + 
        ' comparten mac origen y timestamp de las capturas'  
    }
    return diccionario
        

def claseAdiccionarioCopiaIndividual(comprobacion):
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'Passed': comprobacion.passed,
        'Comentario': 'Esta captura no ha pasado la comprobacion'  
    }
            
        
def comprobacionanual(path_cap1,comprobacion):
    time = timestamps(path_cap1)
    if not str(comprobacion.year) in str(time[0]):
        comprobacion.atrtime = False
        logging.warning(f'La captura {path_cap1} NO tiene el año {comprobacion.year}')
 
def comprobaciontemporal(path_cap1, path_cap2,comprobacion):
    time1 = timestamp(path_cap1)
    time2 = timestamp(path_cap2)       
    if time1 == time2:
        logging.info('Las capturas tienen exactamente los mismos tiempos de captura')
        comprobacion.atrtime = False
        comprobacion.igual= '{path_cap2}'
    else:
        for i in range(len(time1[0])): 
         for j in range(len(time2[0])):
             if time1[0][i] == time2[0][j]:
                 if time1[1][i] == time2[1][j]:
                     logging.info('Las capturas tienen los mismos tiempos de captura----------------------------------------------------')
                     comprobacion.atrtime = False
                     comprobacion.igual= '{path_cap2}'
                     return
    



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




if __name__ == "__main__":
    os.system('cls')
    print('TFG JP ')
    main()

