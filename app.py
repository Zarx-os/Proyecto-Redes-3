from flask import Flask, request, jsonify, send_file
from red import Red
import logging
import os
import json
import pexpect
import re
import time
import  threading
from router import Router

# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', handlers=[logging.FileHandler('app.log')])
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

app = Flask(__name__)
red = None

stop_event = threading.Event()
interval = 5 * 60 

def ssh_command(ip, username, password, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    ssh.close()
    return output, error


def telnet_command(ip, username, password, command):
    # inicie la conexión Telnet
    child = pexpect.spawn('telnet {}'.format(ip))
    child.expect('Username: ')
    child.sendline(username)
    child.expect('Password: ')
    child.sendline(password)
    child.expect('#')
    # envíe el comando y capture la salida
    child.sendline(command)
    child.expect('#')
    # capture la salida anterior a la última expectativa
    output = child.before.decode('utf-8')
    # cierre la conexión Telnet
    child.sendline('exit')
    child.close()
    return output, ''
#Se obtiene los usuarios ded los todos lo usuarios
@app.get('/usuarios')
def get_users():

    ip_list=[]
    with open('routers.json', 'r') as f:
        data = json.load(f)

    for router in data["direcciones"]:
        ip_list.append(data["direcciones"][router][0])


    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}
    for ip in ip_list:
        command = 'sh run | s username'
        output,error = telnet_command(ip, username,password,command)
        #output, error = ssh_command(ip, username, password, command)
        #command2 = 'sh run | s hostname'
        #output2, error2 = ssh_command(ip, username, password,command2)

        if error:
            return jsonify({'error': error}), 500

        matches = re.findall(r'username (\S+) privilege (\d+)', output)
        match = re.search(r'(\S+)\s*$', output)
        user_list=[]
        if match:
            device=match.group(1)
        for match in matches:
            # crear un diccionario con los valores encontrados
            user_dict = {}
            user_dict['username'] = match[0]
            user_dict['privilege'] = match[1]
            user_list.append(user_dict)

        users["users"].append({'router':device,"users":user_list}) 
        
        #Esta version funciona para ssh
        #users["users"].append({'router':output2[output2.index("hostname")+len("hostname")+1:].strip('\r\n'),'ip': ip, 'users': [x[x.index("username")+len("username")+1:x.index("privilege")-1] for x in (i for i in output.strip('\n').split('\n'))]})
        #Esta version es para telnet

    with open('users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)
    return jsonify(users), 200

## Se crean los usuarios en todos los routers
@app.post("/usuarios")
def create_users():
    ip_list=[]
    with open('routers.json', 'r') as f:
        data = json.load(f)
        
    for router in data["direcciones"]:
        ip_list.append(data["direcciones"][router][0])
    
    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}


    credenciales = request.get_json()
    user_create = credenciales['username']
    privilege_create = credenciales['privilege']
    pass_create = credenciales['password']


    for ip in ip_list:

        # Inicia la conexión Telnet
        child = pexpect.spawn('telnet {}'.format(ip), encoding='utf-8')
        child.expect('Username:')
        child.sendline(username)
        child.expect('Password:')
        child.sendline(password)
        child.expect('#')

        # Agrega el usuario
        child.sendline('configure terminal')
        child.expect('#')
        child.sendline('username '+user_create+' privilege '+privilege_create+ ' password ' +pass_create)
        child.expect('#')
        child.sendline('exit')
        child.expect('#')
        child.sendline('write memory')
        child.expect('#')

        # Cierra la conexión Telnet
        child.sendline('exit')

        command = 'sh run | s username'
        output,error = telnet_command(ip, username,password,command)
        matches = re.findall(r'username (\S+) privilege (\d+)', output)
        match = re.search(r'(\S+)\s*$', output)
        user_list=[]
        if match:
            device=match.group(1)
        for match in matches:
            # crear un diccionario con los valores encontrados
            user_dict = {}
            user_dict['username'] = match[0]
            user_dict['privilege'] = match[1]
            user_list.append(user_dict)

        users["users"].append({'router':device,"users":user_list}) 

    with open('users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

    return jsonify(users), 200


##Se actualiza el usuario en todos los routers CHECARRRRRRR
@app.put("/usuarios")
def update_users():
    ip_list=[]
    with open('routers.json', 'r') as f:
        data = json.load(f)
        
    for router in data["direcciones"]:
        ip_list.append(data["direcciones"][router][0])
    
    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}


    credenciales = request.get_json()
    user_update = credenciales['username']
    privilege_update = credenciales['new_privilege']
    pass_update = credenciales['new_password']


    for ip in ip_list:

        # Inicia la conexión Telnet
        child = pexpect.spawn('telnet {}'.format(ip), encoding='utf-8')
        child.expect('Username:')
        child.sendline(username)
        child.expect('Password:')
        child.sendline(password)
        child.expect('#')

        # Agrega el usuario
        child.sendline('configure terminal')
        child.expect('#')
        child.sendline('username '+user_update+' privilege '+privilege_update+ ' password ' +pass_update)
        child.expect('#')
        child.sendline('exit')
        child.expect('#')
        child.sendline('write memory')
        child.expect('#')

        # Cierra la conexión Telnet
        child.sendline('exit')

        command = 'sh run | s username'
        output,error = telnet_command(ip, username,password,command)
        matches = re.findall(r'username (\S+) privilege (\d+)', output)
        match = re.search(r'(\S+)\s*$', output)
        user_list=[]
        if match:
            device=match.group(1)
        for match in matches:
            # crear un diccionario con los valores encontrados
            user_dict = {}
            user_dict['username'] = match[0]
            user_dict['privilege'] = match[1]
            user_list.append(user_dict)

        users["users"].append({'router':device,"users":user_list}) 

    with open('users.json', 'w', encoding='utf-8') as f:
       json.dump(users, f, ensure_ascii=False, indent=4)
    return jsonify(users), 200

#Se elimina el usuario en todos los routers
@app.delete("/usuarios")
def delete_users():
    ip_list=[]
    with open('routers.json', 'r') as f:
        data = json.load(f)
        
    for router in data["direcciones"]:
        ip_list.append(data["direcciones"][router][0])
    
    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}


    credenciales = request.get_json()
    user_delete = credenciales['username']



    for ip in ip_list:
        # Inicia la conexión Telnet
        child = pexpect.spawn('telnet {}'.format(ip), encoding='utf-8')
        child.expect('Username:')
        child.sendline(username)
        child.expect('Password:')
        child.sendline(password)
        child.expect('#')

        # Elimina el usuario
        child.sendline('configure terminal')
        child.expect('#')
        child.sendline('no username '+user_delete)
        child.expect('#')
        child.sendline('exit')
        child.expect('#')
        child.sendline('write memory')
        child.expect('#')

        # Cierra la conexión Telnet
        child.sendline('exit')

        command = 'sh run | s username'
        output,error = telnet_command(ip, username,password,command)
        matches = re.findall(r'username (\S+) privilege (\d+)', output)
        match = re.search(r'(\S+)\s*$', output)
        user_list=[]
        if match:
            device=match.group(1)
        for match in matches:
            # crear un diccionario con los valores encontrados
            user_dict = {}
            user_dict['username'] = match[0]
            user_dict['privilege'] = match[1]
            user_list.append(user_dict)

        users["users"].append({'router':device,"users":user_list}) 

    with open('users.json', 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)
    return jsonify(users), 200


#Obtienen la informacion de todos los routers
@app.get("/routes")
def routers():
    with open('data.json', "r") as f:
        data=json.load(f)
    user = data['user']
    password = data['password']

    with open('routers.json', 'r') as f:
        data = json.load(f)


    # Conectarse al router utilizando telnet
    ip_list=[]
    with open('routers.json', 'r') as f:
        data = json.load(f)
        
    for router in data["direcciones"]:
        ip_list.append(data["direcciones"][router][0])

    router_info=[]

    for router_ip in ip_list:
        child = pexpect.spawn('telnet {}'.format(router_ip))
        child.expect('Username:')
        child.sendline(user)
        child.expect('Password:')
        child.sendline(password)
        child.expect('#')

        # Obtener el nombre del dispositivo
        child.sendline('show run | include hostname')
        child.expect('#')
        output = child.before.decode()
        hostname = output.split()[7]

        # Obtener la dirección IP de loopback
        child.sendline('show ip interface brief | include Loopback')
        child.expect('#')
        output = child.before.decode()
        if len(output.split()) == 8:
            loopback_ip="None"
        else:
            loopback_ip = output.split()[1]

        # Obtener la dirección IP administrativa de todas las interfaces activas
        child.sendline('show ip interface brief | exclude unassigned')
        child.expect('#')
        output = child.before.decode()

        lines = output.splitlines()[2:]
        lines.pop()
        admin_ips = [line.split()[1] for line in lines]

        # Obtener información sobre el sistema operativo
        child.sendline('terminal length 0')
        child.expect('#')
        child.sendline('show version')
        child.expect('#')
        output = child.before.decode()
        for line in output.splitlines():
            if 'Cisco IOS Software' in line:
                os_info = line.split(',')[1].strip()
                company = line.split(',')[0]
                break

        # Obtener información sobre las interfaces activas
        child.sendline('show ip route connected')
        child.expect('#')
        output = child.before.decode()
        interfaces = {}
        lines = output.splitlines()[1:]
        lines.pop()
        for line in lines:
            if len(line.split()) == 6:
                interface = line.split()[5]
                network = line.split()[1]
                interfaces[interface] = network

        router_info.append({"name":hostname,"loopback":loopback_ip,"di_admin":admin_ips,"OS":os_info,"company":company,"int_act":interfaces})
        # Imprimir la información obtenida
        
    return jsonify({"routes":router_info}),200

#Obtetiene la informaciion de un router especifico
@app.get("/routers/<hostname>")
def routers_devices(hostname):
    
    ip_router=None
    with open('routers.json', 'r') as f:
        data = json.load(f)

    for router in data["direcciones"]:
        if hostname == router:
            ip_router=data["direcciones"][router][0]
    
    if ip_router == None:
        return jsonify({"Error":"No se encontro el router solicitado"}) , 404

    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    router_info=[]

    
    child = pexpect.spawn('telnet {}'.format(ip_router))
    child.expect('Username:')
    child.sendline(username)
    child.expect('Password:')
    child.sendline(password)
    child.expect('#')
    # Obtener el nombre del dispositivo
    child.sendline('show run | include hostname')
    child.expect('#')
    output = child.before.decode()
    hostname = output.split()[7]
    # Obtener la dirección IP de loopback
    child.sendline('show ip interface brief | include Loopback')
    child.expect('#')
    output = child.before.decode()
    if len(output.split()) == 8:
        loopback_ip="None"
    else:
        loopback_ip = output.split()[1]
    # Obtener la dirección IP administrativa de todas las interfaces activas
    child.sendline('show ip interface brief | exclude unassigned')
    child.expect('#')
    output = child.before.decode()
    lines = output.splitlines()[2:]
    lines.pop()
    admin_ips = [line.split()[1] for line in lines]
    # Obtener información sobre el sistema operativo
    child.sendline('terminal length 0')
    child.expect('#')
    child.sendline('show version')
    child.expect('#')
    output = child.before.decode()
    for line in output.splitlines():
        if 'Cisco IOS Software' in line:
            os_info = line.split(',')[1].strip()
            company = line.split(',')[0]
            break
    # Obtener información sobre las interfaces activas
    child.sendline('show ip route connected')
    child.expect('#')
    output = child.before.decode()
    interfaces = {}
    lines = output.splitlines()[1:]
    lines.pop()
    for line in lines:
        if len(line.split()) == 6:
            interface = line.split()[5]
            network = line.split()[1]
            interfaces[interface] = network
    router_info.append({"name":hostname,"loopback":loopback_ip,"di_admin":admin_ips,"OS":os_info,"company":company,"int_act":interfaces})
    # Imprimir la información obtenida
        
    return jsonify({"routes":router_info}),200


@app.get("/routers/<hostname>/interfaces")
def router_interfaces(hostname):
    # Definir las credenciales de Telnet y la dirección IP del router
    with open('data.json', "r") as f:
        data=json.load(f)
    user = data['user']
    password = data['password']

    with open('routers.json', 'r') as f:
        data = json.load(f)


    # Conectarse al router utilizando telnet
    ip_list=[]
    with open('routers.json', 'r') as f:
        data = json.load(f)
        
    for router in data["direcciones"]:
        ip_list.append(data["direcciones"][router][0])

    router_interfaces=[]

    for ip in ip_list:
        # Crear la sesión Telnet utilizando pexpect
        tn = pexpect.spawn("telnet " + ip)
        tn.expect("Username:")
        tn.sendline(user)
        tn.expect("Password:")
        tn.sendline(password)
        tn.expect("#")
        # Ejecutar el comando "show interfaces" para obtener la información de todas las interfaces
        
        tn.sendline('show run | include hostname')
        tn.expect('#')
        output = tn.before.decode()
        hostname = output.split()[7]
        tn.sendline("terminal length 0")
        tn.expect("#")

        tn.sendline("show interfaces")
        tn.expect("#")
        output = tn.before.decode("utf-8")
        # Buscar todas las entradas de interfaz en la salida del comando
        interfaces = re.findall(r"^(FastEthernet\d/\d).*?Internet address is (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2}).*?(up|down).*?$", output, re.DOTALL | re.MULTILINE)

        # Imprimir la información de cada interfaz
        
        for interface in interfaces:
            router_interfaces.append({"name":hostname,"Interfaz":interface[0],"Ip":interface[1],"Mask":interface[2],"State":interface[3]})

        # Ejecutar el comando "show cdp neighbors" para obtener la información de los vecinos CDP
        tn.sendline("show cdp neighbors")
        tn.expect("#")
        output = tn.before.decode("utf-8")


    return jsonify({"router_interfaces":router_interfaces}),200

#Se obtiene todos los usuarios en un Router especifico
@app.get('/routers/<hostname>/usuarios')
def get_users_router(hostname):
    ip_router=None
    with open('routers.json', 'r') as f:
        data = json.load(f)

    for router in data["direcciones"]:
        if hostname == router:
            ip_router=data["direcciones"][router][0]
    
    if ip_router == None:
        return jsonify({"Error":"No se encontro el router solicitado"}) , 404

    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}

    command = 'sh run | s username'
    output,error = telnet_command(ip_router, username,password,command)
        #output, error = ssh_command(ip, username, password, command)
        #command2 = 'sh run | s hostname'
        #output2, error2 = ssh_command(ip, username, password,command2)

    if error:
        return jsonify({'error': error}), 500

    matches = re.findall(r'username (\S+) privilege (\d+)', output)
    match = re.search(r'(\S+)\s*$', output)
    user_list=[]
    if match:
        device=match.group(1)
    for match in matches:
        # crear un diccionario con los valores encontrados
        user_dict = {}
        user_dict['username'] = match[0]
        user_dict['privilege'] = match[1]
        user_list.append(user_dict)

    users["users"].append({'router':device,"users":user_list}) 
        
        #Esta version funciona para ssh
        #users["users"].append({'router':output2[output2.index("hostname")+len("hostname")+1:].strip('\r\n'),'ip': ip, 'users': [x[x.index("username")+len("username")+1:x.index("privilege")-1] for x in (i for i in output.strip('\n').split('\n'))]})
        #Esta version es para telnet

    return jsonify(users), 200

#Se crea un usuarios en un Router especifico
@app.post('/routers/<hostname>/usuarios')
def create_user_router(hostname):
    ip_router=None
    with open('routers.json', 'r') as f:
        data = json.load(f)

    for router in data["direcciones"]:
        if hostname == router:
            ip_router=data["direcciones"][router][0]
    
    if ip_router == None:
        return jsonify({"Error":"No se encontro el router solicitado"}) , 404

    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}

    credenciales = request.get_json()
    user_create = credenciales['username']
    privilege_create = credenciales['privilege']
    pass_create = credenciales['password']

    # Inicia la conexión Telnet
    child = pexpect.spawn('telnet {}'.format(ip_router), encoding='utf-8')
    child.expect('Username:')
    child.sendline(username)
    child.expect('Password:')
    child.sendline(password)
    child.expect('#')
    # Agrega el usuario
    child.sendline('configure terminal')
    child.expect('#')
    child.sendline('username '+user_create+' privilege '+privilege_create+ ' password ' +pass_create)
    child.expect('#')
    child.sendline('exit')
    child.expect('#')
    child.sendline('write memory')
    child.expect('#')
    # Cierra la conexión Telnet
    child.sendline('exit')
    command = 'sh run | s username'
    output,error = telnet_command(ip_router, username,password,command)
    matches = re.findall(r'username (\S+) privilege (\d+)', output)
    match = re.search(r'(\S+)\s*$', output)
    user_list=[]
    if match:
        device=match.group(1)
    for match in matches:
        # crear un diccionario con los valores encontrados
        user_dict = {}
        user_dict['username'] = match[0]
        user_dict['privilege'] = match[1]
        user_list.append(user_dict)
    users["users"].append({'router':device,"users":user_list}) 

    # Cargamos el JSON en un diccionario
    with open('users.json', "r") as f:
        user_data=json.load(f)


    # Buscamos el objeto del router R2 en la lista
    router = next((x for x in user_data['users'] if x['router'] == 'R2'), None)

    # Si encontramos el objeto del router, añadimos el usuario a su lista de usuarios
    if router:
        router['users'].append({"username": user_create, "privilege": privilege_create})

    # Guardamos el JSON modificado
    with open('users.json', 'w') as f:
        json.dump(user_data, f, indent=4)

    return jsonify(users), 200

#Actualiza un usuarios existente en el router especifico
@app.put('/routers/<hostname>/usuarios')
def update_user_router(hostname):
    ip_router=None
    with open('routers.json', 'r') as f:
        data = json.load(f)

    for router in data["direcciones"]:
        if hostname == router:
            ip_router=data["direcciones"][router][0]
    
    if ip_router == None:
        return jsonify({"Error":"No se encontro el router solicitado"}) , 404

    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}

    credenciales = request.get_json()
    user_update = credenciales['username']
    privilege_update = credenciales['privilege']
    pass_update = credenciales['password']

    with open('users.json', "r") as f:
        user_data=json.load(f)

    # buscamos el objeto del router
    router = None
    for r in user_data["users"]:
        if r["router"] == hostname:
            router = r
            break

    # verificamos si el usuario existe en el arreglo de usuarios del router
    user_exists = False
    if router is not None:
        for u in router["users"]:
            if u["username"] == user_update:
                user_exists = True
                break

    # imprimimos el resultado
    if user_exists:
        print(f"El usuario {user_update} existe en el router {hostname}")
        # Inicia la conexión Telnet
        child = pexpect.spawn('telnet {}'.format(ip_router), encoding='utf-8')
        child.expect('Username:')
        child.sendline(username)
        child.expect('Password:')
        child.sendline(password)
        child.expect('#')

        # Agrega el usuario
        child.sendline('configure terminal')
        child.expect('#')
        child.sendline('username '+user_update+' privilege '+privilege_update+ ' password ' +pass_update)
        child.expect('#')
        child.sendline('exit')
        child.expect('#')
        child.sendline('write memory')
        child.expect('#')
        # Cierra la conexión Telnet
        child.sendline('exit')
        command = 'sh run | s username'
        output,error = telnet_command(ip_router, username,password,command)
        matches = re.findall(r'username (\S+) privilege (\d+)', output)
        match = re.search(r'(\S+)\s*$', output)
        user_list=[]
        if match:
            device=match.group(1)
        for match in matches:
            # crear un diccionario con los valores encontrados
            user_dict = {}
            user_dict['username'] = match[0]
            user_dict['privilege'] = match[1]
            user_list.append(user_dict)
        users["users"].append({'router':device,"users":user_list}) 

        
        
        # buscar el usuario específico en el array de usuarios del router
        for user in router["users"]:
            if user["username"] == user_update:
                # cambiar el nivel de privilegio del usuario
                user["privilege"] = privilege_update
        
        
        # Guardamos el JSON modificado
        with open('users.json', 'w') as f:
            json.dump(user_data,f, indent=4)

        return jsonify(users), 200
    else:
        print(f"El usuario {username} no existe en el router {hostname} por lo que no se puede modificar")
        return jsonify({"error":"No se puede actualizar el usuario"})

#Se elimina un usuario en el router especifico
@app.delete('/routers/<hostname>/usuarios')
def delete_user_router(hostname):
    ip_router=None
    with open('routers.json', 'r') as f:
        data = json.load(f)

    for router in data["direcciones"]:
        if hostname == router:
            ip_router=data["direcciones"][router][0]
    
    if ip_router == None:
        return jsonify({"Error":"No se encontro el router solicitado"}) , 404

    with open('data.json', "r") as f:
        cre_data=json.load(f)

    username = cre_data["user"]
    password = cre_data["password"]

    users = {'users':[]}

    credenciales = request.get_json()
    user_delete = credenciales['username']


    # Cargamos el JSON en un diccionario
    with open('users.json', "r") as f:
        user_data=json.load(f)

    # buscamos el objeto del router
    router = None
    for r in user_data["users"]:
        if r["router"] == hostname:
            router = r
            break

    # verificamos si el usuario existe en el arreglo de usuarios del router
    user_exists = False
    if router is not None:
        for u in router["users"]:
            if u["username"] == user_delete:
                user_exists = True
                break

    if user_exists:
        print(f"El usuario {username} existe en el router {hostname}")
        # Inicia la conexión Telnet
        child = pexpect.spawn('telnet {}'.format(ip_router), encoding='utf-8')
        child.expect('Username:')
        child.sendline(username)
        child.expect('Password:')
        child.sendline(password)
        child.expect('#')
        # Elimina el usuario
        child.sendline('configure terminal')
        child.expect('#')
        child.sendline('no username '+user_delete)
        child.expect('#')
        child.sendline('exit')
        child.expect('#')
        child.sendline('write memory')
        child.expect('#')
        # Cierra la conexión Telnet
        child.sendline('exit')
        command = 'sh run | s username'
        output,error = telnet_command(ip_router, username,password,command)
        matches = re.findall(r'username (\S+) privilege (\d+)', output)
        match = re.search(r'(\S+)\s*$', output)
        user_list=[]
        if match:
            device=match.group(1)
        for match in matches:
            # crear un diccionario con los valores encontrados
            user_dict = {}
            user_dict['username'] = match[0]
            user_dict['privilege'] = match[1]
            user_list.append(user_dict)
        users["users"].append({'router':device,"users":user_list}) 

        # Si encontramos el objeto del router, buscamos el usuario en su lista de usuarios
        if router:
            user = next((x for x in router['users'] if x['username'] == user_delete), None)
            if user:
                # Si encontramos el usuario, lo eliminamos de la lista de usuarios del router
                router['users'].remove(user)

        # Guardamos el JSON modificado
        with open('users.json', 'w') as f:
            json.dump(user_data, f, indent=4)


        return jsonify(users), 200
    else:
        print(f"El usuario {username} no existe en el router {hostname} por lo que no se puede modificar")
        return jsonify({"error":"No se puede eliminar el usuario"})


#Se obtiene la información de la topologia
@app.get('/topologia')
def obtenerInfoTopologia():
    
    #infoTopologia = red.obtenerRouters()

    with open('data.json', "r") as f:
        data=json.load(f)

    ip = data['ip']
    name = data['name']
    user = data['user']
    password = data['password']
    Red,Direcciones = Router(ip=ip, name=name, user=user, password=password).buscarVecinos(visited=set(), stack=[])
    
    with open('routers.json', 'w', encoding='utf-8') as f:
        json.dump({"red":Red,"direcciones":Direcciones}, f, ensure_ascii=False, indent=4)
    return jsonify({"Routers":Red,"Direcciones":Direcciones},200)

# Creamos una función para explorar la red
def explore_network():

    while not stop_event.is_set():
        # Función de exploración de la red
        print("Explorando red...")   
        with open('data.json', "r") as f:
            data=json.load(f)
    
        ip = data['ip']
        name = data['name']
        user = data['user']
        password = data['password']
        Red,Direcciones = Router(ip=ip, name=name, user=user, password=password).buscarVecinos(visited=set(), stack=[])
        
        with open('routers.json', 'w', encoding='utf-8') as f:
            json.dump({"red":Red,"direcciones":Direcciones}, f, ensure_ascii=False, indent=4)   
        
        time.sleep(interval)



# Creamos una ruta para activar el hilo de exploración
@app.post('/topologia')
def start_exploration():
    global stop_event
    stop_event.clear()
    threading.Thread(target=explore_network, daemon=True).start()
    return jsonify({"message": "Daemon iniciado correctamente"})

# Creamos una ruta para cambiar el intervalo de exploración
@app.put('/topologia')
def change_interval():
    global interval

    credenciales = request.get_json()

    new_interval = credenciales['interval']

    if not new_interval:
        return jsonify({"error": "Falta el parámetro 'interval'"}), 400
    interval = int(new_interval) * 60
    return jsonify({"message": f"Intervalo cambiado a {interval} segundos"})

# Creamos una ruta para detener el hilo de exploración
@app.delete('/topologia')
def stop_exploration():
    global stop_event
    stop_event.set()
    return jsonify({"message": "Daemon detenido correctamente"})


#Se obtiene la grafica de la topologia
@app.get('/topologia/grafica')
def obtenerTopologia():
    #""" Se obtiene la grafica de la topologia"""
    # Obteniendo credenciales desde la petición
    # Recordatorioo esta informacion se leera desde el archivo data.json
    #credenciales = request.get_json()
    #ip = credenciales['ip']
    #name = credenciales['name']
    #user = credenciales['user']
    #password = credenciales['password']
    #------------------

    with open('data.json', "r") as f:
        data=json.load(f)

    ip = data['ip']
    name = data['name']
    user = data['user']
    password = data['password']

    # Asignando crecentiales a la red
    global red 
    red = Red(ip, name, user, password)
    
    # Leyendo la topologia
    if os.path.exists('static/topologia.jpg'):
        return send_file('static/topologia.jpg' )
    else:
        red.leerTopologia() # almacena en el archivo topologia.jpg
        return send_file('static/topologia.jpg')
   

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=5020)