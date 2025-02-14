##Primer Boceto TFG
##Autor: Javier Pérez
##Fecha: 13/02/2025
##Versión: 0.1

##Actualemente estoy trabajando en: Igualdades.py
##Notas: filecmp puede ser útil para comparar archivos
##Ahorro de recursos: comprobacion una vez, pasar a carpteta CORRECTA 
##Nota: despues de abrir el archivo, cerrarlo
##Duda: De que paquete compruebo el timestamp? ping?
##Problema: VlanID
##Nota: al crear el array de macs, el primer elemento es el que me interesa
import os
import pyshark
version = 0.1
def main():
    print("EJecutando el programa")
    

class Comprobacion:
     def __init__(self, atrmac=False, atrtime=False, attr3=False):
        self.atrmac = atrmac
        self.atrtime = atrtime
        self.attr3 = attr3
        
        
        
def dir():
    if not os.path.exists('capturas'):
        os.mkdir('capturas')
    else:
        print('El directorio capturas ya existe :)')
        


def analizar_capturas(path_cap1, path_cap2):
    cap1 = pyshark.FileCapture(path_cap1)
    cap2 = pyshark.FileCapture(path_cap2)
            
    # Aquí puedes agregar el análisis que desees realizar con las capturas
    print(f"Analizando {path_cap1} y {path_cap2}")
            
    mac1 = resultadomac(cap1)
    mac2 = resultadomac(cap2)
            
    cap1.close()
    cap2.close()
    


def resultadomac(cap):
    macs = []
    for pkt in cap:
        if hasattr(pkt, 'eth'):
            macs.append(pkt.eth.src)
    return macs








if __name__ == "__main__":
    main()
    os.system('cls')
    print('TFG JP ' +'\n' + 'version = ' + str(version) + '')
    print('Comprobando directorio de capturas')
    dir()
