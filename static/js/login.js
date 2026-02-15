document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("loginForm");

    form.addEventListener("submit", async function (e) {
        e.preventDefault();

        const username = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        try {
            // Creamos un objeto URLSearchParams para formato x-www-form-urlencoded
            const formData = new URLSearchParams();
            // FastAPI OAuth2 siempre espera el campo 'username'
            formData.append('username', username);
            formData.append('password', password);

            const tokenResponse = await fetch("/api/v1/auth/token", {
                method: "POST",
                headers: {
                    // Cambiamos el tipo de contenido
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                // Enviamos el objeto URLSearchParams directamente
                body: formData
            });

            if (!tokenResponse.ok) {
                // Es bueno leer el error que devuelve el server
                const errorData = await tokenResponse.json();
                console.error("Error del servidor:", errorData);
                throw new Error("Credenciales inválidas");
            }

            const data = await tokenResponse.json();
            const accessToken = data.access_token;
            const tokenType = data.token_type;
            console.log(`Token Recibido: ${accessToken}`)
            
            // 3️⃣ Informar Acceso
            alert("Login successful!");

            // 4️⃣ Redirigir al endpoint protegido
            window.location.href = "/api/v1/dashboard";

        } catch (error) {
            alert("Error en autenticación: " + error.message);
        }
    });

});