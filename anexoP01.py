import random
def PrintLista(lista): #OJO CON ******
    print(lista)#HORIZONTAL
    #for i in lista:
     #   print(i)
     #VERTICAL  

def pruebax(a,b):
    total = a*b
    return total

    
def ListaOrdenada(lista):
    #COMPROBACION 
    resultado = True
    for i in range(0,len(lista)-1): #CUIDADO, si pusieramos for i in lista
        if lista[i] > lista[i+1]:   # recorreria los elementos, no el indice
            resultado = False
    return resultado

def OrdenBubble(lista):
    #FUNCIONAAAA
    while(not ListaOrdenada(lista)):
        for i in range(0,len(lista)-1):
            if lista[i] > lista[i+1]:
                aux1 = lista[i]
                aux2 = lista[i+1]
                lista[i] = aux2
                lista[i+1] = aux1
    return lista



def OrdenSelection(lista):
    #FUNCIONAAAA
    minindex= 0
    cambio = False
    min = max(lista)
    for i in range(0,len(lista)):
        min = lista[i]
        for j in range(i,len(lista)):
         if min > lista[j]:
                cambio = True
                min = lista[j]
                minindex = j
        if cambio:
         aux1 = lista[minindex]
         aux2 = lista[i]
         lista[i] = aux1
         lista[minindex] = aux2
         cambio = False     
    return lista
        
        
def bogosort(lista):
    while(not ListaOrdenada(lista)):
        shuffle(lista)
    return lista

def shuffle(lista):
    n = len(lista)
    for i in range(0,n):
        r = random.randint(0,n-1)
        lista[i], lista[r] = lista[r], lista[i]
    return lista


#Hecho por Copilot
def OrdenInsertion(lista):
    for i in range(1, len(lista)):
        key = lista[i]
        j = i - 1
        while j >= 0 and key < lista[j]:
            lista[j + 1] = lista[j]
            j -= 1
        lista[j + 1] = key
    return lista

