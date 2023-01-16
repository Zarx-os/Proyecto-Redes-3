/* LISTENERS */
// Documento
document.addEventListener('DOMContentLoaded', cargarTopologia);

/* FUNCIONES */
async function cargarTopologia() { // Consultamos la API para obtener la topologia
    const response = await fetch('/topologia',
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                'ip': '192.168.0.1',
                'name': 'Host',
                'user': 'admin',
                'password': 'admin1234'
            })
        }
    );
    // Obtenemos la imagen y la asignamos
    const blob = await response.blob();
    document.querySelector("#img-topo").src = window.URL.createObjectURL(blob);
};
