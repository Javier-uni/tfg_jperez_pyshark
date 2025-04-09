import os
import subprocess
import logging
path2 = subprocess.check_output("pwd", shell=True, text=True)


def main():
    # Configuramos el logging básico
 logging.basicConfig(
    level=logging.INFO, # Solo mensajes de INFO en adelante
    format='%(levelname)s: %(message)s'
    )

 logging.debug("Este mensaje no aparecerá porque el nivel es INFO.")
 logging.info("Este mensaje SÍ se mostrará.")
 logging.warning("Mensaje de warning.")
 logging.error("Mensaje de error.")
 logging.critical("Mensaje crítico.")    
    
 path = os.getcwd()
 for i in range(1,3):
  print(path)
  print(path2)
 
 a = str(8)
 b = 8
 c = '8'
 print(a == b) # False
 print(a == c) # True
 print(b == c) # False
 
 
 
 
 
def print_hi(msg):
    print(f'Hi, {msg}')
     
 
if __name__ == '__main__':
 os.system('cls')
 print_hi('PyCharm')
 main()