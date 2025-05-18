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


version = 0.8
def Inicio(directorio,practica):
    #Es necesario async para pyshark por lo que antes de Inio debo llamar a async_wrapper
    print("EJecutando el programa")
    dir(directorio)
    
    #Incluir aqui las comprobaciones en funcion de la practica
    #prueba in practica2 ???
    if practica == 'practica 2' or practica == 'Practica 2':
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
     level = level_dict.get(level, logging.INFO),  # Default a INFO si hay error
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
 console_handler.setLevel(level_dict.get(level, logging.critical))  # Ajustar el nivel del handler
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
        The year associated with the capture (default is '2025').
        
    atrcopia : bool, optional
        A boolean attribute indicating if there has been a copy (default is True).
        
    atrexact : bool, optional
        A boolean attribute indicating if there has been an exact copy(default is True).
        
    igual : str, optional
        A string attribute that points the name of the copied capture (default is an empty string).
        
    passed : bool, optional
        A boolean attribute indicating if the verification passed (default is True).
    
    nota : int, optional
        A numeric attribute (default is 0).
        
    Methods
    -------
    __init__(self, name, atrmac=True, atrtime=True, year='2025', atrcopia=True, atrexact=True, igual='', passed=True)
        Initializes the Comprobacion class with the provided attributes.
    """
    
    def __init__(self, name, atrmac=True, atrtime=True, year='2025', 
                  atrcopia=True, atrexact=True, igual='', passed=True, nota=0):
        self.name = name 
        self.atrmac = atrmac
        self.atrtime = atrtime
        self.year = year
        self.atrcopia = atrcopia 
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
   


        
def recorrerDirectorioFinal(directorio,prueba):
    
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
    
    #COMPROBACION INDIVIDUAL
    logging.info('Comprobacion individual')
    diccionariomacs = {}
    for i in range(len(archivos)):
        comprobacionindividual(archivos[i],comprobaciones[i],prueba)

        #Extraccion de MACs y paso a diccionario
        nombre = comprobaciones[i].name
        macs = lib.resultadomacsrc(archivos[i])  
        diccionariomacs[nombre] = macs
        
        
    #COMPROBACION DE PARES
    nombres = list(diccionariomacs.keys())

    for i in range(len(nombres)):
        for j in range(i+1, len(nombres)):
            logging.info(f"Comparando {nombres[i]} y {nombres[j]}")
            lib.comprobacionIdentica(archivos[i], archivos[j], comprobaciones[i],comprobaciones[j])
            

            if (diccionariomacs[nombres[i]] == diccionariomacs[nombres[j]]) and \
               (diccionariomacs[nombres[i]] != 0) and \
               (not(comprobaciones[i].atrexact == False) or not(comprobaciones[j].atrexact == False)):
                # REVISAR SI ES == O IN
                
                comprobaciones[i].atrmac = False
                comprobaciones[j].atrmac = False
                logging.info(f"{nombres[i]} y {nombres[j]} tienen las mismas MACs: {diccionariomacs[nombres[i]]}")
                comprobaciontemporal(archivos[i], archivos[j], comprobaciones[i], comprobaciones[j])

             
    #COMPROBACION DE PARES
    exponerResultados(comprobaciones)   
    json_to_pdf(prueba)





##Analisis de las capturas Individual y llamamiento a pares  
def comprobacionindividual(path_cap1,comprobacion,prueba):
    """
    Checks if a capture file makes the minimun requirements.

    Parameters:
        path_cap1 (str): The file path of the capture to be checked.
        comprobacion (object): An object with attributes `atrmac`, `atrtime`, `year`, and `atrcopia` that will be updated based on the checks.
        prueba (str): The name of the prueba.

    """
    
    logging.info('Analizando captura: '+str(path_cap1))
    if prueba == 'practica 2' or prueba == 'Practica 2':
        lib.comprobacionanual(path_cap1,comprobacion)
        lib.MinPacks(path_cap1,comprobacion, numMin = 4)  #contar en funcion de IMCP
        #lib.MinMacsSrc(path_cap1,comprobacion)  #Es del Router no del PC (maaaal) (probablemente quitar)
        #Comentar con Carlos, ICMP echo req y reply?
        lib.minPacksVlan(path_cap1, comprobacion, numMin=4) #Change name, varias comprobaciones 1.(802.1.q) Que exista paquete con vlan
        #2. Correspondencia de Vlan con el fichero json (con 1 correcto)
        #3. COmprobacion complementaria -> Paquete ICMP E Request (mirar IP origen) 10.0.X.Y1 XXXXXXXXXXXXX 
        #RESPUESTA (request respond)
        lib.comprobacionARP(path_cap1,comprobacion) #Comprobacion de ARP FALTARIA RELACIONARLO CON 10.220.X.Y
        lib.comprobacionICMP(path_cap1,comprobacion)
    
    elif True:
        logging.critical('FALTAAAAA')
        logging.critical('De momento solo funciona la Practica 2')
        #recorrerDirectorioFinal(directorio)



        
    
    
    

 
 
               
##Exponer resultados en un json       
def exponerResultados(comprobaciones):
    logging.debug('Exponiendo resultados')
    listado_diccionarios = []
    listado_hechos = []
    with open('resultados.json', 'w') as file:
     for comprobacion in comprobaciones:
        
        logging.debug('Exponiendo captura: '+comprobacion.name + ' si procede')
        if (not comprobacion.atrexact) and (comprobacion.name not in listado_hechos):
            listado_hechos.append(comprobacion.igual)
            logging.debug(f'La captura {comprobacion.name}  es una copia exacta, siendo expuesta')
            diccionario = lib.claseAdiccionarioCopiaExacta(comprobacion)
            listado_diccionarios.append(diccionario)
        else:
            if (not comprobacion.atrcopia) and (comprobacion.name not in listado_hechos):
                listado_hechos.append(comprobacion.igual)
                logging.debug(f'La captura {comprobacion.name}  es una copia')
                diccionario = lib.claseAdiccionarioCopia(comprobacion)
                listado_diccionarios.append(diccionario)
            else:
             if (not comprobacion.passed) and (comprobacion.name not in listado_hechos):
                listado_hechos.append(comprobacion.igual)
                logging.debug(f'La captura {comprobacion.name}  no ha pasado la comprobacion')
                diccionario = lib.claseAdiccionarioCopiaIndividual(comprobacion)
                listado_diccionarios.append(diccionario)
     json.dump(listado_diccionarios, file, indent=4)
         
             

 
 
 
##Comprobaciones Específicas      
#REVISAR SI == O IN ---------------------------------------------------------------------
def comprobaciontemporal(path_cap1, path_cap2,comprobacion1,comprobacion2):
    time1 = lib.timestamp(path_cap1)
    time2 = lib.timestamp(path_cap2) 
    sigue = False      
    if time1 == time2:
        logging.warning('Las capturas tienen exactamente los mismos tiempos de captura')
        comprobacion1.atrtime = False
        comprobacion1.igual= os.path.basename(path_cap2)
        comprobacion1.passed = False
        
        comprobacion2.atrtime = False
        comprobacion2.igual= os.path.basename(path_cap1)
        comprobacion2.passed = False
        
    else:
        for i in range(len(time1[0])): 
            for j in range(len(time2[0])):
                if (time1[0][i] == time2[0][j]) and not sigue:
                    if time1[1][i] == time2[1][j]:
                        sigue = True
                        logging.warning('Las capturas tienen los mismos tiempos de captura('+comprobacion1.name+'y'+comprobacion2.name+')')
                        comprobacion1.atrtime = False
                        comprobacion1.atrcopia = False
                        comprobacion1.igual= os.path.basename(path_cap2)
                        comprobacion1.passed = False
                     
                     
                        comprobacion2.atrtime = False
                        comprobacion2.atrcopia = False
                        comprobacion2.igual= os.path.basename(path_cap1)
                        comprobacion2.passed = False
                        break
                
    



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

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        for i, item in enumerate(data, 1):
            if isinstance(item, dict):  # Ensure item is a dictionary
                pdf.set_font("Arial", style='B', size=14)  # Cambia la fuente a Arial, negrita, tamaño 14
                pdf.cell(0, 10, f"Copia Detectada: {i}", ln=True)

                pdf.set_font("Arial", style='', size=12)  # Cambia la fuente a Arial, normal, tamaño 12
                pdf.cell(0, 10, f"Captura1: {item.get('nombre', '')}", ln=True)
                pdf.cell(0, 10, f"Captura2: {item.get('igual', '')}", ln=True)
                pdf.cell(0, 10, f"AtrMAC: {item.get('atrmac', '')}", ln=True)
                pdf.cell(0, 10, f"Copia: {item.get('copia', '')}", ln=True)
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
    opciones = ['Practica 1', 'Practica 2', 'Practica 3']
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


