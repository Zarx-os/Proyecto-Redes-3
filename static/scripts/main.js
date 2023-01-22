/* LISTENERS */
// Documento
//document.addEventListener('DOMContentLoaded', cargarTopologia);



document.getElementById("demo").addEventListener("click", myFunction);
document.getElementById("demo1").addEventListener("click", myFunction2);


function myFunction() {
    sessionStorage.setItem('boton', true);
    document.getElementById('contenedor_user').style.display = "block";
    document.getElementById("user").value="";
    document.getElementById("pass").value="";
}
function myFunction2(){
    cargarTopologia(sessionStorage.getItem('user'),sessionStorage.getItem('pass'));
    document.location.reload(true);
}

if(sessionStorage.getItem('boton') == 'true'){
    document.getElementById("demo").disabled = true;
    document.getElementById("demo").style.backgroundColor = '#764b4f';
}

document.getElementById('btn_can').addEventListener("click",function() {
    document.getElementById('contenedor_user').style.display = "none";
    sessionStorage.removeItem('explorar');
    sessionStorage.removeItem('boton');
  });
  document.getElementById('btn_acce').addEventListener("click",function() {
    Verify()
  });


window.addEventListener("click",function(event) {
    if (event.target == this.document.getElementById('contenedor_user')) {
      this.document.getElementById('contenedor_user').style.display = "none";
    }
  });

function Verify() {
    var user =  document.getElementById("user").value;
    var pass = document.getElementById("pass").value;
    
    if(user.leght == 0 || pass.leght == 0){
        alert('Esta vacio');
    }else{
        sessionStorage.setItem('user',user);
        sessionStorage.setItem('pass',pass);
        cargarTopologia(user,pass);
        document.getElementById("demo").disabled = true;
        document.getElementById("demo").style.backgroundColor = '#764b4f';
        document.getElementById('contenedor_user').style.display = "none";
    }
  };
  if(sessionStorage.getItem('boton')=='true'){
    cargarTopologia(sessionStorage.getItem('user'),sessionStorage.getItem('pass'));
  }



/* FUNCIONES */
async function cargarTopologia(user, pass) { // Consultamos la API para obtener la topologia
    console.log(user+" "+pass);
    const response = await fetch('/topologia',
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                'ip': '148.204.56.1',
                'name': 'Host',
                'user': user,
                'password': pass
            })
        }
    );
    // Obtenemos la imagen y la asignamos
    const blob = await response.blob();
    document.querySelector("#img-topo").src = window.URL.createObjectURL(blob);
};
