##Primer Boceto TFG
##Autor: Javier Pérez
##Fecha:
##Nota: despues de abrir el archivo, cerrarlo
##NOtas:
## Llamar con parametros
##Comprobar atrMac
import os
import sys
import pyshark
import logging
import json
import filecmp
from fpdf import FPDF
import BibliotecaTFG as lib

version = 0.5
def main():
    print("EJecutando el programa")
    logconfig("info")
    directorio='capturas03'
    dir(directorio)
    recorrerDirectorioFinal(directorio)
    


##Primera Parte del programa, configuracion de logs y directorios

def logconfig(level):
 """
 Configures the logging module to display log messages with a level of INFO or higher.
 The log messages will be formatted to show the log level and the message content.
 """
 if level == 'debug':
     log_level = logging.DEBUG  # Todos los mensajes de log
 elif level == 'info':
     log_level = logging.INFO  # Solo mensajes de INFO en adelante
 elif level == 'warning':
     log_level = logging.WARNING  # Solo mensajes de WARNING en adelante
 elif level == 'error':
     log_level = logging.ERROR  # Solo mensajes de ERROR en adelante
 elif level == 'critical':
     log_level = logging.CRITICAL
 else:
     print('Error en los logs, NO FUNCIONAN')

 logging.basicConfig(
     level=log_level,
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
    
    Nota : int, optional
        A numeric attribute (default is 0).
        
    Methods
    -------
    __init__(self, name, atrmac=True, atrtime=True, year='2025', copia=True, atrexact=True, igual='', passed=True)
        Initializes the Comprobacion class with the provided attributes.
    """
    
    def __init__(self, name,atrmac=True, atrtime=True,year='2025', 
                  copia=True, atrexact=True, igual='',passed=True, nota=0):
        self.name = name 
        self.atrmac = atrmac
        self.atrtime = atrtime
        self.year = year
        self.copia = copia 
        self.atrexact = atrexact
        self.igual = igual
        self.passed = passed #Incluye comprobacion unica y a pares
        self.nota = nota 
        
        
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
   


#Recorrer el directorio 
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
            lib.timestamp(cap_path)
            
def recorrerCapturas(directorio):
    print('El directorio tiene '+str(len(os.listdir(directorio)))+' capturas')
    archivos = [] 
    for filename in os.listdir(directorio):
        archivos.append(str(directorio+'/'+filename))
    for archivo in archivos:
        print('Analizando captura: ' + archivo)
        lib.resultadomacsrc(archivo)
      
        
def recorrerDirectorioFinal(directorio):
    
    logging.info('El directorio tiene '+str(len(os.listdir(directorio)))+' capturas')
    archivos = []
    comprobaciones = []
    
    for filename in os.listdir(directorio):
        archivos.append(str(directorio+'/'+filename))
        comprobacion = Comprobacion(filename)
        comprobaciones.append(comprobacion)
        logging.debug(comprobacion.name)
    # logging.debug(archivos)
    
    logging.debug(len(archivos)) 
    
    
    for i in range(len(archivos)):
        comprobacionindividual(archivos[i],comprobaciones[i])
        for j in range(i, len(archivos)):
            if i != j:#curioso, podemos quitar esta comprobacion si en range ponemos (i+1, len(archivos))
             analizar_capturas(archivos[i], archivos[j],comprobaciones[i])
         
    exponerResultados(comprobaciones)   
    json_to_pdf()





##Analisis de las capturas Individual y llamamiento a pares  
def comprobacionindividual(path_cap1,comprobacion):
    """
    Checks if a capture file makes the minimun requirements.
    Parameters:
    path_cap1 (str): The file path of the capture to be checked.
    comprobacion (object): An object with attributes `atrmac`, `atrtime`, `year`, and `copia` that will be updated based on the checks.
    Returns:
    None
    """
    comprobacionanual(path_cap1,comprobacion)
    lib.MinPacks(path_cap1,comprobacion)
    lib.MinMacsSrc(path_cap1,comprobacion)
    lib.MinPacksVlan(path_cap1,comprobacion)
    
    


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
        logging.warning("Las capturas son idénticas: ")
        logging.warning('  Path 1: '+ str(path_cap1))
        logging.warning('  Path 2: '+ str(path_cap2))
        comprobacion1.atrexact = False
        comprobacion1.passed = False
        comprobacion1.igual= str({path_cap2})
    else:
        logging.debug("Las capturas no son identicas.")
        
        
def analizar_capturas(path_cap1, path_cap2,comprobacion):      
    # Aquí puedes agregar el análisis que desees realizar con las capturas
    logging.info(f"Analizando {path_cap1} y {path_cap2}")
    comprobacionIdentica(path_cap1, path_cap2, comprobacion)
    if  comprobacion.atrexact:
     mac1 = lib.resultadomacsrc(path_cap1)
     mac2 = lib.resultadomacsrc(path_cap2)
     if mac1 == mac2:
        comprobacion.atrmac = False
        comprobaciontemporal(path_cap1, path_cap2,comprobacion)
        
        
               
##Exponer resultados en un json       
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
        'Comentario': 'Esta captura es una copia exacta de:'+ str(comprobacion.igual) 
    }
    return diccionario


def claseAdiccionarioCopia(comprobacion):
    diccionario = {
        'nombre': comprobacion.name,
        'atrmac': comprobacion.atrmac,
        'copia': comprobacion.copia,
        'Comentario': 'Esta captura es una copia de: '+ str(comprobacion.igual) + 
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
    return diccionario
            
 
 
##Comprobaciones Específicas       
def comprobacionanual(path_cap1,comprobacion):
    time = lib.timestamps(path_cap1)
    if not str(comprobacion.year) in str(time[0]):
        comprobacion.atrtime = False
        logging.warning(f'La captura {path_cap1} NO tiene el año {comprobacion.year}')
        
        
def comprobaciondepaquetes(path_cap1,comprobacion):
    cap = pyshark.FileCapture(path_cap1)
    if len(cap) < 2:
        comprobacion.passed = False
        logging.warning(f'La captura {path_cap1} NO tiene el numero de paquetes necesario')
    else:
        logging.info(f'La captura {path_cap1} tiene el numero de paquetes necesario')
    cap.close()
 
def comprobaciontemporal(path_cap1, path_cap2,comprobacion):
    time1 = lib.timestamp(path_cap1)
    time2 = lib.timestamp(path_cap2)       
    if time1 == time2:
        logging.warning('Las capturas tienen exactamente los mismos tiempos de captura')
        comprobacion.atrtime = False
        comprobacion.igual= str({path_cap2})
        comprobacion.passed = False
    else:
        for i in range(len(time1[0])): 
         for j in range(len(time2[0])):
             if time1[0][i] == time2[0][j]:
                 if time1[1][i] == time2[1][j]:
                     logging.warning('Las capturas tienen los mismos tiempos de captura')
                     comprobacion.atrtime = False
                     comprobacion.copia = False
                     comprobacion.igual= str({path_cap2})
                     comprobacion.passed = False
                     return
    



##Json a pdf
def json_to_pdf(json_path='resultados.json', output_pdf_path='resultados.pdf'):
    """
    Converts a JSON file to a PDF report.
    
    Args:
        json_path (str): Path to the input JSON file.
        output_pdf_path (str): Path to save the generated PDF file.
    """
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        for i, item in enumerate(data, 1):
            pdf.set_font("Arial", style='B', size=14)  # Cambia la fuente a Arial, negrita, tamaño 14
            pdf.cell(0, 10, f"Problema {i}", ln=True)

            pdf.set_font("Arial", style='', size=12)  # Cambia la fuente a Arial, normal, tamaño 12
            pdf.cell(0, 10, f"Nombre: {item.get('nombre', '')}", ln=True)
            pdf.cell(0, 10, f"AtrMAC: {item.get('atrmac', '')}", ln=True)
            pdf.cell(0, 10, f"Copia: {item.get('copia', '')}", ln=True)
            pdf.multi_cell(0, 10, f"Comentario: {item.get('Comentario', '')}")
            pdf.ln(7)  # espacio entre capturas
        



        # Nueva página: Leyenda de los atributos
        pdf.add_page()
        pdf.set_font("Arial", style='B', size=14)
        pdf.cell(0, 10, "Leyenda de atributos de la clase Comprobacion", ln=True)

        pdf.set_font("Arial", style='', size=12)
        pdf.multi_cell(0, 10, """\
En el proceso de verificación, cada captura de red se representa con un objeto de la clase Comprobacion. Estos son algunos de sus atributos:

- atrmac (bool): Indica si la MAC de origen detectada no está repetida en otra captura con el mismo tiempo. Si es False, significa que se encontró otra captura con la misma MAC y se considera duplicado.

- copia (bool): Indica si la captura se considera una copia parcial de otra. Se pone en False cuando la MAC y el 'timestamp' coinciden parcialmente con otra captura.

- atrexact (bool): Indica si dos capturas son exactamente iguales (mismo contenido de archivos). Si pasa a False, significa que son idénticas.

- igual (str): Apunta al nombre (o path) de la captura de la que es copia o con la que coincide en alguna verificación.

- passed (bool): Indica si la captura supera las validaciones (por ejemplo, año, MAC única, contenido esperado). Si se vuelve False, no pasa la verificación.

- Comentario (str): En el informe JSON/PDF, se incluye un texto explicativo que describe la razón del fallo, la duplicidad, etc.
""")


        pdf.output(output_pdf_path)
        logging.info(f"PDF generado: {output_pdf_path}")
    except FileNotFoundError:
        logging.error(f"El archivo JSON {json_path} no existe.")
    except Exception as e:
        logging.error(f"Error al generar el PDF: {e}")
        



if __name__ == "__main__":
    os.system('cls')
    print('TFG JP ' +'\n' + 'version = ' + str(version) + '')
    if len(sys.argv) > 1:
     order = str(sys.argv[1]).lower()
     if order in ['practica2', 'p2']:
        main() 
     elif order in ['practica1', 'p1']:
         print('En proceso')
     elif order in ['practica3', 'p3']:
         print('En proceso')
    else:
        print('No se ha encontrado el argumento correcto')
        print('De momento ejecuto P2')
        main

