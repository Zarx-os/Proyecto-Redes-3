import pexpect
import getpass
import logging
import time
import re


class Router:

    

    def __init__(self, ip, name, user="admin", password="admin1234"):
        self.ip = ip
        self.name = name
        self.user = user
        self.password = password
        self.routers={}
        self.direcciones={}

    def buscarVecinos(self, visited=set(), stack=[], child=''):
        #child = pexpect.spawn('telnet ' + self.ip)
        #child.expect('Username: ')
        #child.sendline(self.user)
        #child.expect('Password: ')
        #child.sendline(self.password)
        child = pexpect.spawn('ssh '+self.user+'@'+ self.ip)
        child.expect('Password: ')
        child.sendline(self.password)
        child.expect('#')
        child.sendline('sh run | i host')
        child.expect("#")
        info_host = child.before.decode().split()
        hostname = info_host[len(info_host)-1]
        self.name = hostname
        #print('Conecto a '+hostname)
        # routers[self.name].update({"user": self.user, "password": self.password, "conectados": {}, "interfaces": {}})
        self.dfs2(visited, self.routers, self.name,self.direcciones,stack,child)
        return self.routers,self.direcciones
        # interfaces = []
        # [interfaces.append(x) for x in tabla_dispositivos if ("/" in x) and (x not in interfaces)]  # Agrega a la lista si tiene / y no repetidos

        # """ Registramos el router """
        # routers[self.name] = {"conectados": {x.split(".")[0]:'' for x in conectados}, "interfaces": interfaces}
        # Guardamos la info del dispositivo
        # """ Obtenemos la informacion de cada dispositivo conectado """

    def dfs2(self,visited, routers, node ,direcciones , stack, child):
        
        di_ip=None
        if node not in visited:
            if node != 'R3':
                
                if node in direcciones.keys():
                    di_ip=direcciones[node]
                #child.sendline('telnet ' + di_ip[len(di_ip)-1])
                child.sendline('ssh -l '+self.user+' '+di_ip[len(di_ip)-1])
                #print(di_ip[len(di_ip)-1])
                #child.expect('Username: ')
                #child.sendline(self.user)
                child.expect('Password: ')
                child.sendline(self.password)
                #print('Conecto a '+node + ' ' + di_ip)
                child.expect(node+'#')

            
            
            visited.add(node)

            routers , direcciones = self.vecinos(routers,node,direcciones,child)
            #print(routers[node)
            stack.append(node)
            for neighbour in routers[node]: 
                print(node+'->'+neighbour)
                #print(stack)
                
                #if len(routers[node]) == 1:
                #    continue

                if stack[-1] != node:
                    while stack[-1] != node:
                        stack.pop()
                        child.sendline('exit')
                        child.expect('#')

                self.dfs2(visited, routers, neighbour,direcciones,stack,child)

                

            

            


    def vecinos(self,routers,node,direcciones,child):
        # Obtenemos la tabla de dispositivos
        
        child.sendline('show cdp ne | begin Device')

        child.expect(node+"#")
        tabla_dispositivos = child.before.decode().split()

        # Agrega a la lista si tiene la palabra Enrutador
        #conectados = [x for x in tabla_dispositivos if "Enrutador" in x]
        conectados = [str(re.search('(^R[0-9])+', w).group()) for w in tabla_dispositivos if re.search('(^R[0-9])+', w)]
        routers[node]=conectados
        
        for dispositivo in conectados:
            # Obtenemos la info del dispositivo
            child.sendline('sh cdp entry ' + dispositivo+'.adminredes.escom.ipn.mx')
            child.expect(node+"#")
            info_dispositivo = child.before.decode().split()

            # Obtenemos la ip del dispositivo
            ip = None
            for linea in range(0, len(info_dispositivo)):
                if 'address:' == info_dispositivo[linea]:
                    ip = info_dispositivo[linea+1]
                    if dispositivo not in direcciones.keys():
                        direcciones[dispositivo]=[str(ip)]
                    else:
                        conectado=direcciones[dispositivo]
                        conectado.append(str(ip))
                        direcciones[dispositivo]=conectado

               
            # Examinamos los routers vecinos

        return routers,direcciones

    def configurarSNMP(self):
        mensaje = "Conectando a " + self.name
        logging.debug(mensaje)

        # """ Nos conectamos al router """
        child = pexpect.spawn('telnet ' + self.ip)
        child.expect('Username: ')
        child.sendline(self.user)
        child.expect('Password: ')
        child.sendline(self.password)

        # """ Configuramos el snmp"""
        child.expect(self.name+">")
        child.sendline("snpm-server comunity | i snmp")
        child.expect(self.name+">")
        child.sendline("snmp-server enable traps snmp linkdown linkup")
        child.expect(self.name+">")
        child.sendline("snmp-server host 192.168.1.3 version 2c comun_pruebas")
        child.expect(self.name+">")

    # def monitorear(self,intefaz, periodo):
    #    pass
