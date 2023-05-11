from router import Router
import logging
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

class Red():

    def __init__(self, ip, name, user="admin", password="admin1234"):
        self.ip = ip
        self.name = name
        self.user = user
        self.password = password
        self.stack = []
        self.visited = set()

    def leerTopologia(self):
        # Obteniendo información de los routers
        Grafico_red,Grafico_direcciones = Router(self.ip, self.name, self.user, self.password).buscarVecinos(self.visited, self.stack)
        
        #print(Grafico_red)
        #print(Grafico_direcciones)
        #router_cercano = routersGraph(1,0,0,"admin","admin1234", child=None)
        # Generando gráfico
        plt.clf() # Limpiando imagen
        #plt.figure(figsize=(6, 6))
        G = nx.Graph()
        for router in Grafico_red.keys(): # Agregando routers
            G.add_node(router, name=router)
        for r1 in Grafico_red: # Generando conexiones
            for r2 in Grafico_red[r1]:
                G.add_edge(r1,r2)

        nx.draw_networkx(G, with_labels=True, node_size=1000,node_color="skyblue", node_shape="s", alpha=0.8, linewidths=10) # Creando gráfico
        plt.box(False)
        plt.axis('off')
        plt.savefig("static/topologia.jpg")
    
    def obtenerRouters(self):
        return self.routers
