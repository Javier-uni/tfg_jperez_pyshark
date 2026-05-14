##TFG
##Autor: Javier Pérez
##Fecha:

import os
import sys
import pyshark
import logging
import json
import filecmp
from fpdf import FPDF
import BibliotecaTFG as lib
import tkinter
from tkinter import scrolledtext
import threading
import asyncio


version = 0.99
def Inicio(directorio,practica):
    #Es necesario async para pyshark por lo que antes de Inio debo llamar a async_wrapper
    print("EJecutando el programa")
    dir(directorio)
    
    #Incluir aqui las comprobaciones en funcion de la practica
    #prueba in practica2 ???
    if practica == 'practica 2' or practica == 'Practica 2' or True: #LIMPIARRRRRR
        #Recorrer el directorio y analizar las capturas
        #recorrerDirectorio(directorio)
        #recorrerCapturas(directorio)
        recorrerDirectorioFinal(directorio,practica)
        
        
    elif True:
        logging.critical('FALTAAAAA')
        logging.critical('De momento solo funciona la Practica 2')
        #recorrerDirectorioFinal(directorio)
    


##Primera Parte del programa, configuracion de logs y directorios

def logconfig(level):
 """
 Configures the logging module to display log messages with a level of INFO or higher.
 The log messages will be formatted to show the log level and the message content.
 """
 level_dict = {
        'debug': logging.DEBUG,         # Todos los mensajes de log
        'info': logging.INFO,           # Solo mensajes de INFO en adelante
        'warning': logging.WARNING,     # Solo mensajes de WARNING en adelante
        'error': logging.ERROR,         # Solo mensajes de ERROR en adelante
        'critical': logging.CRITICAL    # Solo mensajes de CRITICAL 
    }
    
#Cambia la configuracion inicial de los logs
#No llega a funcionar ya que los logger creados los edito más tarde a mi gusto
 logging.basicConfig(
     level = level_dict.get(level, logging.DEBUG),  # Default a INFO si hay error
     format='%(levelname)s: %(message)s'
 )
 
 #Saco logger para poder borrar los handlers
 logger = logging.getLogger()
 
 # Limpiar handlers existentes
 for handler in logger.handlers[:]:
     logger.removeHandler(handler)
     
 # Handler para consola (formato simple)
 console_handler = logging.StreamHandler() 
 console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
 console_handler.setLevel(level_dict.get(level, logging.CRITICAL))  # Ajustar el nivel del handler
 logger.addHandler(console_handler)
 
 

def logexmpl():
 """
 Example of how to use the logging module.
 """
 logging.debug("Este mensaje no aparecerá porque el nivel es INFO.")
 logging.info("Este mensaje SÍ se mostrará.")
 logging.warning("Mensaje de warning.") #Default
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
        The year associated with the capture (default is '2026').
        
    atrComprobacionGlobal : bool, optional
        A boolean attribute indicating if there has been a copy (default is True).
        
    atrexact : bool, optional
        A boolean attribute indicating if there has been an exact copy(default is True).
        
    igual : str, optional
        A string attribute that points the name of the copied capture (default is an empty string).
        
    atrComprobacionIndividual : bool, optional
        A boolean attribute indicating if the verification atrComprobacionIndividual (default is True).
    
    atrCorrupted : bool, optional
        A boolean attribute indicating if the capture is corrupted (default is False).
    
    codigo : str, optional
        A string attribute (default is '000').
        
    Methods
    -------
    __init__(self, name, atrmac=True, atrtime=True, year='2026', atrcopia=True, atrexact=True, igual='', atrCorrupted=False, atrComprobacionIndividual=True, codigo='000')
        Initializes the Comprobacion class with the provided attributes.
    """
    
    def __init__(self, name, atrmac=True, atrtime=True, year='2026', 
                  atrcopia=True, atrexact=True, igual='', atrCorrupted=False, atrComprobacionIndividual=True, codigo='000'):
        self.name = name 
        self.atrmac = atrmac
        self.atrtime = atrtime
        self.year = year
        self.atrComprobacionGlobal = atrcopia   
        self.atrexact = atrexact
        self.igual = igual
        self.atrComprobacionIndividual = atrComprobacionIndividual
        self.atrCorrupted = atrCorrupted
        self.codigo = codigo  
        
        
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
   


#falta la Documentacion aqui... curro
def recorrerDirectorioFinal(directorio,prueba):
    """
    Analyzes all capture files contained in a directory.

    This function performs the complete analysis workflow for a given practice.
    First, it creates the initial list of capture files and their associated
    Comprobacion objects. Then it pass through several stages of filtering and validation,
    including checking for corrupted captures, running individual checks, and comparing captures in pairs to detect copies.

    The analysis is divided into five main stages:
        1. Build the original lists of capture paths and Comprobacion objects.
        2. Filter corrupted captures before processing them.
        3. Run the individual validation checks over valid captures.
        4. Compare valid captures in pairs to detect exact copies or possible
           copies based on source MAC addresses and timestamps.
        5. Generate the final JSON and PDF reports.

    Args:
        directorio (str): Path to the directory containing the capture files.
        prueba (str): Name of the practice or analysis mode to be applied.

    Returns:
        None: The function updates the Comprobacion objects, writes the
        results to a JSON file, and generates a PDF report.
    """

    
    logging.info('El directorio tiene '+str(len(os.listdir(directorio)))+' capturas')
    archivos = []
    comprobaciones = []
    
    diccionariomacs = {}
    
    # 1. Crear listas originales
    for filename in os.listdir(directorio):
        #Probar en vez de str -> path = os.path.join(directorio, filename)
        archivos.append(str(directorio+'/'+filename))
        comprobacion = Comprobacion(filename)
        comprobaciones.append(comprobacion)
        logging.debug(comprobacion.name)
    
    logging.debug(len(archivos)) 
    
    
    
    #2. Creamos listas filtradas
    archivos_validos = []
    comprobaciones_validas = []
    
    for i in range(len(archivos)):
        # Validar si el archivo es corrupto antes de procesarlo
        if lib.is_capture_corrupted(archivos[i]):
            logging.critical(f'Saltando archivo corrupted: {archivos[i]}')
            comprobaciones[i].atrCorrupted = True
            comprobaciones[i].atrComprobacionIndividual = False
            comprobaciones[i].codigo = '404'
        else: 
            archivos_validos.append(archivos[i])
            comprobaciones_validas.append(comprobaciones[i])
    logging.debug(f'Capturas válidas para análisis: {len(archivos_validos)}')
            
            
            
            
    #3. Comprobacion individual
    logging.info('Comprobacion individual')
    for i in range(len(archivos_validos)):    
        comprobacionindividual(archivos_validos[i],comprobaciones_validas[i],prueba)

        #3.5 Extraccion de MACs y paso a diccionario
        nombre = comprobaciones_validas[i].name
        macs = lib.resultadomacsrc(archivos_validos[i])  
        diccionariomacs[nombre] = macs
        
        
    #4. Comprobacion de pares 
    nombres = list(diccionariomacs.keys())

    for i in range(len(nombres)):
        for j in range(i+1, len(nombres)):
            logging.info(f"Comparando {nombres[i]} y {nombres[j]} de manera Identica")

            lib.comprobacion_identica(archivos_validos[i], archivos_validos[j], 
                                      comprobaciones_validas[i], comprobaciones_validas[j])
            

            if (diccionariomacs[nombres[i]] == diccionariomacs[nombres[j]]) and \
                (diccionariomacs[nombres[i]] != 0) and \
                (diccionariomacs[nombres[j]] != 0) and \
               (not(comprobaciones_validas[i].atrexact == False) or not(comprobaciones_validas[j].atrexact == False)):
                # REVISAR SI ES == O IN
                
                comprobaciones_validas[i].atrmac = False
                comprobaciones_validas[j].atrmac = False
                logging.info(f"{nombres[i]} y {nombres[j]} tienen las mismas MACs: {diccionariomacs[nombres[i]]}")
                lib.comparacionTemporal(archivos_validos[i], archivos_validos[j], 
                                        comprobaciones_validas[i], comprobaciones_validas[j])

             
     # 5. Informe
    exponerResultados(comprobaciones)   
    json_to_pdf(prueba)




def comprobacionindividual(path_cap1,comprobacion,prueba):
    """
    Checks if a capture file makes the minimun requirements.
    In order to check the requirements, the cap will be put under a list of tests (depending on the prueba)

    Parameters:
        path_cap1 (str): The file path of the capture to be checked.
        comprobacion (object): An object with attributes `atrmac`, `atrtime`, `year`, and `atrComprobacionIndividual` that will be updated based on the checks.
        prueba (str): The name of the prueba.

    """
    
    logging.info('Analizando captura: '+str(path_cap1))
    if prueba == 'practica 2' or prueba == 'Practica 2':
        lib.check_older(path_cap1,comprobacion)
        lib.num_captured_pckts(path_cap1, comprobacion, numMin = 4)  #contar en funcion de IMCP
        #lib.min_macs_src(path_cap1,comprobacion)  #Es del Router no del PC (maaaal) (probablemente quitar)
        #Comentar con Carlos, ICMP echo req y reply?
        lib.num_vlan_captured_pckts(path_cap1, comprobacion, numMin=4) #Change name, varias comprobaciones 1.(802.1.q) Que exista paquete con vlan
        #2. Correspondencia de Vlan con el fichero json (con 1 correcto)
        #3. COmprobacion complementaria -> Paquete ICMP E Request (mirar IP origen) 10.0.X.Y1 XXXXXXXXXXXXX 
        #RESPUESTA (request respond)
        lib.check_arp_request_reply(path_cap1,comprobacion) #Comprobacion de ARP FALTARIA RELACIONARLO CON 10.220.X.Y
        lib.check_ip_vlan(path_cap1,comprobacion)
        lib.check_vlan_802_1q(path_cap1,comprobacion) 
    elif prueba == "informe" or prueba == '0':
        logging.info('Comprobacion individual de informe')
        lib.check_older(path_cap1,comprobacion)
        logging.info('La captura '+str(path_cap1)+' ha pasado la comprobacion individual')

        
    elif prueba == 'Tagged':
        logging.debug('Comprobacion individual de '+str(prueba))
        lib.num_captured_pckts(path_cap1, comprobacion, numMin = 4)  
        lib.check_older(path_cap1,comprobacion)
        #lib.check_ip_vlan(path_cap1,comprobacion)
        lib.num_vlan_captured_pckts(path_cap1, comprobacion, numMin=4)
        lib.check_arp_request_reply(path_cap1,comprobacion)
        #lib.check_vlan_802_1q(path_cap1,comprobacion) 
        logging.info('La captura '+str(path_cap1)+' ha pasado la comprobacion individual')
        
        
    elif prueba == 'Untagged':
        logging.debug('Comprobacion individual de '+str(prueba))
        lib.num_captured_pckts(path_cap1, comprobacion, numMin = 4)  
        lib.check_older(path_cap1,comprobacion)
        lib.check_arp_request_reply(path_cap1,comprobacion)
        lib.check_no_vlan_802_1q(path_cap1,comprobacion)
        logging.info('La captura '+str(path_cap1)+' ha pasado la comprobacion individual')
    
    
    elif True:
        logging.critical('FALTAAAAA')
        logging.critical('De momento solo funciona la Practica 2')
        #recorrerDirectorioFinal(directorio)
        



        

def exponerResultados(comprobaciones):
    """
    Creates a JSON file documenting failed or copied network captures.

    Args:
        comprobaciones (list): A list of Comprobacion objects representing network captures
        to be analyzed.

    The function examines each Comprobacion object and writes information to resultados.json 
    for: \n
    - Exact copies of other captures (atrexact = False)
    - Captures that failed individual verification (atrComprobacionIndividual = False)
    - Captures that match MAC addresses or timestamps with others (potential copies)
    
    The JSON output includes details about which captures are copies of others and why they
    failed verification.
    """
    logging.debug('Exponiendo resultados')
    listado_diccionarios = []
    listado_hechos = []
    with open('resultados.json', 'w') as file:
     for comprobacion in comprobaciones:
        logging.debug('Exponiendo captura: '+comprobacion.name + ' si procede')
        if comprobacion.atrCorrupted:
             listado_hechos.append(comprobacion.name)
             logging.debug(f'La captura {comprobacion.name}  está corrupta, siendo expuesta')
             diccionario = lib.claseAdiccionarioCorrupted(comprobacion)
             listado_diccionarios.append(diccionario)
             continue
        
       
        elif (not comprobacion.atrexact) and (comprobacion.name not in listado_hechos):
            listado_hechos.append(comprobacion.igual)
            logging.debug(f'La captura {comprobacion.name}  es una copia exacta, siendo expuesta')
            diccionario = lib.claseAdiccionarioCopiaExacta(comprobacion)
            listado_diccionarios.append(diccionario)
            
        elif(comprobacion.codigo == '040'):
                listado_hechos.append(comprobacion.name)
                logging.debug(f'La captura {comprobacion.name}  no ha pasado la comprobacion de numero minimo de paquetes VLAN')
                diccionario = lib.claseAdiccionarioMinPaquetesVLAN(comprobacion)
                listado_diccionarios.append(diccionario)
                
        elif(comprobacion.codigo == '004'):
                listado_hechos.append(comprobacion.name)
                logging.debug(f'La captura {comprobacion.name}  no es de este año')
                diccionario = lib.claseAdiccionarioYear(comprobacion)
                listado_diccionarios.append(diccionario)
            
        elif(comprobacion.codigo == '410'):
                listado_hechos.append(comprobacion.name)
                logging.debug(f'La captura {comprobacion.name}  no ha pasado la comprobacion de su tag esperado')
                diccionario = lib.claseAdiccionarioUntagged(comprobacion)
                listado_diccionarios.append(diccionario)
                
        elif(comprobacion.codigo == '420'):
                listado_hechos.append(comprobacion.name)
                logging.debug(f'La captura {comprobacion.name}  no ha pasado la comprobacion de su tag esperado')
                diccionario = lib.claseAdiccionarioTag(comprobacion)
                listado_diccionarios.append(diccionario)
                
        else:
            if (not comprobacion.atrComprobacionGlobal) and (comprobacion.name not in listado_hechos):
                listado_hechos.append(comprobacion.igual)
                logging.debug(f'La captura {comprobacion.name}  es una copia')
                diccionario = lib.claseAdiccionarioCopia(comprobacion)
                listado_diccionarios.append(diccionario)
            else:
             if (not comprobacion.atrComprobacionIndividual) and (comprobacion.name not in listado_hechos):
                listado_hechos.append(comprobacion.igual)
                logging.debug(f'La captura {comprobacion.name}  no ha pasado la comprobacion')
                diccionario = lib.claseAdiccionarioCopiaIndividual(comprobacion)
                listado_diccionarios.append(diccionario)
     json.dump(listado_diccionarios, file, indent=4)
         
             

 



    



##Json a pdf
def json_to_pdf(practica,json_path='resultados.json'):
    """
    Converts a JSON file to a PDF report.
    
    Args:
        practica (str): Name of the practica.
        json_path (str): Path to the input JSON file.

    """
    npractica = practica.replace(" ", "")
    output_pdf_path = f"Resultados{npractica}.pdf"
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)

        class ReportPDF(FPDF):
            def header(self):
                """
                Add the DIT logo on every page after the cover.
                """
                if self.page_no() == 1:
                    # Cover
                    return

                logo_path = os.path.join("Images", "DITlogo.png")
                if os.path.exists(logo_path):
                    logo_width = 25  # Keep the logo modest in size
                    x_pos = self.w - self.r_margin - logo_width
                    # Slightly higher than the normal margin to hug the top
                    self.image(logo_path, x=x_pos, y=8, w=logo_width)

        pdf = ReportPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Cover page with full-bleed image
        cover_path = os.path.join("Images", "PortadaPDF.jpg")
        pdf.add_page()
        if os.path.exists(cover_path):
            pdf.image(cover_path, x=0, y=0, w=pdf.w, h=pdf.h)
        else:
            logging.warning(f"No se encontró la portada en {cover_path}.")

        # Content starts on the second page
        pdf.add_page()
        pdf.ln(10)
        pdf.set_font("Arial",style='B', size=16)
        pdf.cell(0, 10, f"Descripción del análisis de capturas") #Título2
        pdf.ln(20)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, """Este programa ha sido desarrollado para analizar automáticamente las capturas de red entregadas por los estudiantes en la práctica, con el objetivo de comprobar que cumplen los requisitos mínimos y detectar posibles copias entre alumnos. 

Su diseño permite realizar un análisis completo sin necesidad de conocimientos avanzados sobre redes o sobre el uso de herramientas como Wireshark.""")#Breve descripción del programa
        pdf.ln(10)
        pdf.multi_cell(0, 10, """\
El programa realiza las siguientes funciones principales:
    1. Comprobación Individual: Cada captura se analiza para verificar que cumple con los requisitos
        mínimos establecidos en la práctica, como la presencia de ciertos tipos de paquetes y
        la veracidad de estos.
        
    2. Detección de Copias: Se comparan las capturas entre sí para identificar posibles copias,
        basándose en atributos inequivocos de estas.
        
    3. Generación de Informes: Los resultados del análisis se documentan en un archivo JSON y se
        genera un informe en formato PDF que refleja los hallazgos principales.
        
Este enfoque automatizado facilita la revisión de las capturas, asegurando una evaluación justa y eficiente de los trabajos entregados por los estudiantes.""")
        pdf.ln(10)
        
        
        
        # Third page: Report content
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        for i, item in enumerate(data, 1):
              # Check if 'igual' is empty
            if isinstance(item, dict):  # Ensure item is a dictionary
                if item.get('igual') != '':
                    pdf.set_font("Arial", style='B', size=14)  # Cambia la fuente a Arial, negrita, tamaño 14
                    pdf.cell(0, 10, f"Problema Detectado: {i}", ln=True)

                    pdf.set_font("Arial", style='', size=12)  # Cambia la fuente a Arial, normal, tamaño 12
                    pdf.cell(0, 10, f"Captura1: {item.get('nombre', '')}", ln=True)
                    pdf.cell(0, 10, f"Captura2: {item.get('igual', '')}", ln=True)
                    #pdf.cell(0, 10, f"AtrMAC: {item.get('atrmac', '')}", ln=True)
                    #pdf.cell(0, 10, f"Copia: {item.get('copia', '')}", ln=True)
                    pdf.multi_cell(0, 10, f"Comentario: {item.get('Comentario', '')}")
                    pdf.ln(7)  # espacio entre capturas
                else:
                    pdf.set_font("Arial", style='B', size=14)  # Cambia la fuente a Arial, negrita, tamaño 14
                    pdf.cell(0, 10, f"Captura Incorrecta Detectada: {i}", ln=True)
                    pdf.set_font("Arial", style='', size=12)  # Cambia la fuente a Arial, normal, tamaño 12
                    pdf.cell(0, 10, f"Captura1: {item.get('nombre', '')}", ln=True)
                    pdf.multi_cell(0, 10, f"Comentario: {item.get('Comentario', '')}")
                    pdf.ln(7)  # espacio entre capturas
                    
            else:
                logging.warning(f"Unexpected data format: {item}")
        



        # Nueva página: Leyenda de los atributos
        pdf.add_page()
        pdf.set_font("Arial", style='B', size=14)
        pdf.cell(0, 10, "Leyenda de atributos de la clase Comprobacion", ln=True)

        pdf.set_font("Arial", style='', size=12)
        pdf.multi_cell(0, 10, """\
En el proceso de verificación, cada captura de red se representa 
con un objeto de la clase Comprobacion. Estos son algunos de sus atributos:

- atrmac (bool): Indica si la MAC de origen detectada no está repetida en otra captura con el mismo tiempo. Si es False, significa que se encontró otra captura con la misma MAC y se considera duplicado.

- copia (bool): Indica si la captura se considera una copia parcial de otra. Se pone en False cuando la MAC y el 'timestamp' coinciden parcialmente con otra captura.

- atrexact (bool): Indica si dos capturas son exactamente iguales (mismo contenido de archivos). Si pasa a False, significa que son idénticas.

- igual (str): Apunta al nombre (o path) de la captura de la que es copia o con la que coincide en alguna verificación.

- atrComprobacionIndividual (bool): Indica si la captura supera las validaciones (por ejemplo, año, MAC única, contenido esperado). Si se vuelve False, no pasa la verificación.

- Comentario (str): En el informe JSON/PDF, se incluye un texto explicativo que describe la razón del fallo, la duplicidad, etc.
""")


        pdf.output(output_pdf_path)
        logging.info(f"PDF generado: {output_pdf_path}")
        logging.info('--------------------------------------------------------------------------')
    except FileNotFoundError:
        logging.error(f"El archivo JSON {json_path} no existe.")
    except Exception as e:
        logging.error(f"Error al generar el PDF: {e}")
        





##GUI
def startGUI():
    """
    Starts the GUI for the program.
    """
    print('Iniciando GUI')
    logconfig("info") # no se si al cambiar a critical afecta al gui
    # Configuración de la ventana principal
    ventana = tkinter.Tk()
    ventana.title('TFG JP')
    ventana.geometry('1200x800') ## Tamaño probablemente no óptimo A CAMBIARRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
    ventana.configure(bg='#F0F0F0')  # Color de fondo suave

    # Estilos 
    estilo_titulo = ('Times New Roman', 20, 'bold')
    estilo_normal = ('Arial', 12)
    color_boton = '#4A7A8C'  # Azul moderno

    # Marco contenedor para mejor organización
    marco_principal = tkinter.Frame(ventana, bg='#F0F0F0')
    marco_principal.pack(pady=20, expand=True)

    # Título con estilo mejorado
    label_titulo = tkinter.Label(
        marco_principal,
        text='Bienvenido a la GUI de TFG JP',
        font=estilo_titulo,
        bg='#F0F0F0', #No seria necesario ya que hereda el color del marco
        fg='#2C3E50'
    )
    label_titulo.pack(pady=15)

    # Sección de directorio
    marco_directorio = tkinter.Frame(marco_principal, bg='#F0F0F0')
    marco_directorio.pack(pady=10)

    # Etiqueta descriptiva
    label_directorio = tkinter.Label(
        marco_directorio,
        text='Directorio a analizar:',
        font=estilo_normal,
        bg='#F0F0F0',
        fg='#34495E'
    )
    label_directorio.pack(anchor='w', pady=5)

    # Cuadro de entrada ampliado
    cuadro_entrada = tkinter.Entry(
        marco_directorio,
        width=60,
        font=estilo_normal,
        bd=2,
        relief=tkinter.GROOVE
    )
    cuadro_entrada.pack(padx=10, pady=5)
    cuadro_entrada.insert(0, 'capturas03')

    # Sección de opciones
    marco_opciones = tkinter.Frame(marco_principal, bg='#F0F0F0')
    marco_opciones.pack(pady=15)

    # Cuadro de selección ampliado
    opciones = ['Practica 1', 'Practica 2', 'Practica 3', 'Tagged', 'Untagged']
    seleccion = tkinter.StringVar()
    seleccion.set(opciones[1])

    label_opciones = tkinter.Label(
        marco_opciones,
        text='Seleccione una opción:',
        font=estilo_normal,
        bg='#F0F0F0',
        fg='#34495E'
    )
    label_opciones.pack(anchor='w', pady=5)

    cuadro_seleccion = tkinter.OptionMenu(
        marco_opciones,
        seleccion,
        *opciones
    )
    cuadro_seleccion.config(
        width=20,
        font=estilo_normal,
        bg='#FFFFFF',
        relief=tkinter.GROOVE
    )
    cuadro_seleccion.pack(padx=10, pady=5, side=tkinter.LEFT)

    # Botón de inicio mejorado
    boton_inicio = tkinter.Button(
        marco_principal,
        text='Iniciar análisis',
        command=lambda: threading.Thread(
            target=async_wrapper_inicio, 
            args=(str(cuadro_entrada.get()), 
                            str(seleccion.get()))).start(),
        font=estilo_normal,
        bg=color_boton,
        fg='white',
        padx=20,
        pady=10,
        bd=0,
        activebackground='#3B5D6C'
    )
    boton_inicio.pack(pady=20)
    
    
    #Resultados
    marco_resultados = tkinter.Frame(ventana, bg='#F0F0F0')
    marco_resultados.pack(fill=tkinter.BOTH, expand=True, padx=20, pady=10)
    
    
    consola_logs = scrolledtext.ScrolledText(
    marco_resultados,
    wrap=tkinter.WORD,
    font=('Consolas', 10),
    bg='#FFFFFF',
    fg='#2C3E50',
    height=10
    )
    consola_logs.pack(fill=tkinter.BOTH, expand=True)
    
    
    #REVISAR IMPORTANTE
    # Añadir handler personalizado para la GUI
    class TextWidgetHandler(logging.Handler):
        def __init__(self, widget):
            super().__init__()
            self.widget = widget
            self.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s: %(message)s',
                datefmt='%Y-%m-%d'))

        def emit(self, record):
            msg = self.format(record)
            def safe_append():
                self.widget.configure(state='normal')
                self.widget.insert(tkinter.END, msg + '\n')
                self.widget.configure(state='disabled')
                self.widget.see(tkinter.END)  # Auto-scroll
            self.widget.after(0, safe_append)  # Usar after para sincronizar
    
    
    # Añadir el handler a logging
    gui_handler = TextWidgetHandler(consola_logs)
    gui_handler.setLevel(logging.INFO)  # Puedes ajustar el nivel independientemente
    logging.getLogger().addHandler(gui_handler)
   
    ventana.mainloop()








def async_wrapper_inicio(directorio, practica):
    # Crea un nuevo event loop para este hilo
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        Inicio(directorio, practica)  
    finally:
        loop.close()  # Limpieza



def main(): #CAMBIAR
    startGUI()

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
        # print('No se ha encontrado el argumento correcto')
        # print('Puedes usar los siguientes argumentos:') 
        # print('practica1, practica2, practica3')
        # print('De momento ejecuto P2')
        # main
        startGUI()
        async_wrapper_inicio('capturas03','practica 2')


