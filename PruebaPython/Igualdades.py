import os
import pyshark
import filecmp



def main():
    print("EJecutando el programa")
    comprobacion1 = Comprobacion()
    # comprobacionIdentica("capturas01/p2-aptd9.pcapng", "capturas01/p2-aptd9-COPIA.pcapng", comprobacion1)
    # print('Comprobación exacta: ' + str(comprobacion1.atrexact))
    directorio='capturas02'
    dir(directorio)
    recorrerDirectorio(directorio)
    

class Comprobacion:
     def __init__(self, atrmac=False, atrtime=False, attr3=False, atrexact=False):
        self.atrmac = atrmac
        self.atrtime = atrtime
        self.attr3 = attr3
        self.atrexact = atrexact
        
          
def dir(directorio):
    """
    Checks if a directory exists, and if not, creates it.
    Args: 
        directorio (str): The name of the directory to check or create.
    If the directory does not exist, it will be created. If it already exists, a message will be printed indicating that the directory already exists.
    """   
    if not os.path.exists(str(directorio)):
        print('El directorio '+str(directorio)+' no existe, creando...')
        os.mkdir(str(directorio))
    else:
        print('El directorio '+str(directorio)+' ya existe :)')
 
 
        
def recorrerDirectorio(directorio):
    print('El directorio tiene '+str(len(os.listdir(directorio)))+' capturas')
    for filename in os.listdir(directorio):
        cap_path = os.path.join(directorio, filename)
        if os.path.isfile(cap_path):
            print('Analizando captura: ' + cap_path)
            rmac(cap_path)
            # vid(cap_path)
            # timestamp(cap_path)



def comprobacionIdentica(path_cap1, path_cap2, comprobacion1):
    #Esto tendre que automatizarlo para que compare todas las capturas del directorio
    #CUIDADO CON LOS PATHS
    abspath1 = os.path.abspath(path_cap1)
    abspath2 = os.path.abspath(path_cap2)
    if filecmp.cmp(abspath1, abspath2, shallow=False):
        print("Las capturas son idénticas: ")
        print('  Path 1: '+ str(path_cap1))
        print('  Path 2: '+ str(path_cap2))
        comprobacion1.atrexact = True
    else:
        print("Las capturas son diferentes.")
        
        




def analizar_capturas(path_cap1, path_cap2):
    cap1 = pyshark.FileCapture(path_cap1)
    cap2 = pyshark.FileCapture(path_cap2)
            
    # Aquí puedes agregar el análisis que desees realizar con las capturas
    print(f"Analizando {path_cap1} y {path_cap2}")
            
    mac1 = resultadomac(cap1)
    mac2 = resultadomac(cap2)
            
    cap1.close()
    cap2.close()
    


def rmac(cap_path):
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
    print(macs)
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
    print(vids)
    cap.close()
    return vids


def timestamp(cap_path):
    fecha = []
    nanosegs = []
    timestamps = [fecha, nanosegs]
    abspath = os.path.abspath(cap_path)
    cap = pyshark.FileCapture(abspath)
    for pkt in cap:
        #no haria ni falta el hasttr
        if hasattr(pkt, 'frame_info'):
            if pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S') not in fecha:
             fecha.append(pkt.sniff_time.strftime('%d/%m/%Y %H:%M:%S'))
             
            if pkt.sniff_timestamp not in nanosegs:
             nanosegs.append(pkt.sniff_timestamp)
            
    print(timestamps)
    cap.close()
    return timestamps


if __name__ == "__main__":
    os.system('cls')
    print('TFG JP ' +'\n' + 'version = '  + '')
    main()

