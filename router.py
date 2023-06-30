import pexpect
import json
import re


class Router:

    def __init__(self, ip, name, user="admin", password="admin1234"):
        self.ip = ip
        self.name = name
        self.user = user
        self.password = password
        self.routers = {}
        self.direcciones = {}

    def buscarVecinos(self, visited=set(), stack=[], child=''):
        # Seccion para hacerlo con Telnet
        child = pexpect.spawn('telnet ' + self.ip)
        child.expect('Username: ')
        child.sendline(self.user)
        child.expect('Password: ')
        child.sendline(self.password)

        # Seccion para hacerlo con SSH
        #child = pexpect.spawn('ssh '+self.user+'@' + self.ip)
        #child.expect('Password: ')
        #child.sendline(self.password)
        # ------
        child.expect('#')
        child.sendline('sh run | i host')
        child.expect("#")
        info_host = child.before.decode().split()
        hostname = info_host[len(info_host)-1]
        self.name = hostname
        self.dfs2(visited, self.routers, self.name,
                  self.direcciones, stack, child)
        return self.routers, self.direcciones

    def dfs2(self, visited, routers, node, direcciones, stack, child):

        di_ip = None
        with open('data.json', "r") as f:
            data = json.load(f)
        host = data['name']

        if node not in visited:

            if node != host:
                if node in direcciones.keys():
                    di_ip = direcciones[node]
                    try:
                    # Linea para el telnet
                        child.sendline('telnet ' + di_ip[len(di_ip)-1])
                    # Linea para SSH
                        # child.sendline('ssh -l '+self.user+' '+di_ip[len(di_ip)-1])
                        child.expect('Username: ')
                        child.sendline(self.user)
                        child.expect('Password: ')
                        child.sendline(self.password)
                        child.expect(node+'#')
                    except pexpect.exceptions.EOF:
                        print('No se pudo conectar al router vecino: ' + node)
                        return
            visited.add(node)

            routers, direcciones = self.vecinos(
                routers, node, direcciones, child)
            # print(routers[node)
            stack.append(node)
            for neighbour in routers[node]:
                print(node+'->'+neighbour)

                if stack[-1] != node:
                    while stack[-1] != node:
                        stack.pop()
                        child.sendline('exit')
                        child.expect('#')

                self.dfs2(visited, routers, neighbour,
                          direcciones, stack, child)

    def vecinos(self, routers, node, direcciones, child):
        # Obtenemos la tabla de dispositivos

        child.sendline('show cdp ne | begin Device')

        child.expect(node+"#")
        tabla_dispositivos = child.before.decode()

        lines = tabla_dispositivos.splitlines()

        # Ignorar la primera línea que contiene el encabezado de las columnas
        lines = lines[1:]

        # Extraer los valores del campo "Device ID" de cada línea
        device_ids = [line.split()[0] for line in lines]

        print(device_ids[1:])


        # Agrega a la lista si tiene la palabra Enrutador
        # conectados = [x for x in tabla_dispositivos if "Enrutador" in x]
        #conectados = [str(re.search('(^R[0-9])+', w).group())for w in tabla_dispositivos if re.search('(^R[0-9])+', w)]
        conectados = device_ids[1:]
        routers[node] = conectados

        for dispositivo in conectados:
            # Obtenemos la info del dispositivo
            # child.sendline('sh cdp entry ' + dispositivo+'.adminredes.escom.ipn.mx')
            child.sendline('sh cdp entry ' + dispositivo)
            child.expect(node+"#")
            info_dispositivo = child.before.decode().split()

            # Obtenemos la ip del dispositivo
            ip = None
            for linea in range(0, len(info_dispositivo)):
                if 'address:' == info_dispositivo[linea]:
                    ip = info_dispositivo[linea+1]
                    if dispositivo not in direcciones.keys():
                        direcciones[dispositivo] = [str(ip)]
                    else:
                        conectado = direcciones[dispositivo]
                        conectado.append(str(ip))
                        direcciones[dispositivo] = conectado

            # Examinamos los routers vecinos

        return routers, direcciones
