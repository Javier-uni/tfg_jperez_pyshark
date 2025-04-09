import os
import time
import anexoP01
## CHULETA DE JP PARA PYTHON
# ALGORITMOS DE ORDENACION 
# Mirar anexoP01

os.system('cls')
print('Prueba 01 JP' + '') #el propio print viene con un \n incluido

os.system()

#listas
listaordenada = [0,1,2,3,4]
listaordeninv = [14,3,8,1]
listadesordenada = [1,3,6,2,15,2,0,5,3,7,34,8,5,2,7,5,9,0,8,7]
print(listadesordenada)
print(listaordenada)

#pruebas de anexo
"""
resultado = anexoP01.ListaOrdenada(listaordenada)
print('Prueba de ordenacion, expected true: ' + str(resultado))
resultado = anexoP01.ListaOrdenada(listadesordenada)
print('Prueba de ordenacion, expected false ' + str(resultado))
anexoP01.PrintLista(listadesordenada)
"""
#BubleSort 
#print(anexoP01.OrdenBubble(listadesordenada))
tiempo0 = time.time_ns()
prueba = anexoP01.OrdenSelection(listadesordenada)
print('BubbleSort: ' + str(prueba))
tiempo1 = time.time_ns()
print('      -Tiempo BubbleSort: ' + str(tiempo1-tiempo0))


tiempo0 = time.time_ns()
prueba = anexoP01.OrdenSelection(listadesordenada)
print('SelectioSort: ' + str(prueba))
tiempo1 = time.time_ns()
print('      -Tiempo SelectionSort: ' + str(tiempo1-tiempo0))


tiempo0 = time.time_ns()
prueba = anexoP01.bogosort(listadesordenada)
print('BogoSort: ' + str(prueba))
tiempo1 = time.time_ns()
print('      -Tiempo Bogosort: ' + str(tiempo1-tiempo0))