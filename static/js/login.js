document.addEventListener("DOMContentLoaded", function () {

    // JS LOGIN
    const formLogin = document.getElementById("loginForm");

    formLogin.addEventListener("submit", async function (e) {
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
            //const accessToken = data.access_token;
            //const tokenType = data.token_type;
            //console.log(`Token Recibido: ${accessToken}`)

            // 3️⃣ Informar Acceso
            //alert("Login successful!");

            // 4️⃣ Redirigir al endpoint protegido
            window.location.href = "/api/v1/dashboard";

        } catch (error) {
            alert("Error en autenticación: " + error.message);
        }
    });

    // JS RECOVERY
    const formRecovery = document.getElementById("forgotPasswordForm");

    formRecovery.addEventListener("submit", async function (e) {
        e.preventDefault();
        const email = document.getElementById("email").value;
        const submitBtn = formRecovery.querySelector("button");

        // Feedback visual: Deshabilitar botón
        const originalText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = "<strong>Enviando...</strong>";

        try {
            const response = await fetch("/api/v1/users/forgot-password", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ email: email })
            });

            const data = await response.json();

            if (response.ok) {
                alert(data.message);
                // Opcional: Redirigir al login
                window.location.href = "/";
            } else {
                alert("Error: " + (data.detail || "Ocurrió un error inesperado"));
            }

        } catch (error) {
            alert("Error de conexión: " + error.message);
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    });

    // JS RESET
    const formReset = document.getElementById("resetPasswordForm");

    // Obtener token de la URL (query param ?token=...)
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    if (!token) {
        alert("Token no encontrado o enlace inválido. Por favor solicita un nuevo enlace.");
        // Opcional: Deshabilitar el formulario
        const inputs = formReset.querySelectorAll("input, button");
        inputs.forEach(input => input.disabled = true);
        return;
    }

    formReset.addEventListener("submit", async function (e) {
        e.preventDefault();
        const newPassword = document.getElementById("new_password").value;
        const confirmPassword = document.getElementById("confirm_password").value;
        const submitBtn = formReset.querySelector("button");

        if (newPassword !== confirmPassword) {
            alert("Las contraseñas no coinciden.");
            return;
        }

        // Feedback visual
        const originalText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = "<strong>Enviando...</strong>";

        try {
            const response = await fetch(`/api/v1/users/reset-password/${token}`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ new_password: newPassword })
            });

            const data = await response.json();

            if (response.ok) {
                alert(data.message);
                window.location.href = "/"; // Redirigir al login
            } else {
                alert("Error: " + (data.detail || "Ocurrió un error inesperado"));
            }

        } catch (error) {
            alert("Error de conexión: " + error.message);
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    });


});