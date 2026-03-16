document.addEventListener("DOMContentLoaded", function () {

    // Refactor: Leer configuración desde data-attribute del body
    const BASE_PATH = document.body.getAttribute("data-root-path") || "";

    // Función auxiliar para manejar expiración de sesión (401/403)
    function handleSessionExpiration(response) {
        if (response.status === 401 || response.status === 403) {
            alert("La sesión o el enlace han expirado. Serás redirigido al inicio.");
            window.location.href = `${BASE_PATH}/`;
            return true;
        }
        return false;
    }

    // JS LOGIN
    const formLogin = document.getElementById("loginForm");
    if (formLogin) {
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

                const tokenResponse = await fetch(`${BASE_PATH}/api/v1/auth/token`, {
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
                    const contentType = tokenResponse.headers.get("content-type");
                    if (contentType && contentType.includes("application/json")) {
                        const errorData = await tokenResponse.json();
                        console.error("Error del servidor:", errorData);
                    } else {
                        const errorText = await tokenResponse.text();
                        console.error("Error del servidor (No JSON):", errorText);
                    }
                    if (tokenResponse.status === 404) {
                        throw new Error("Ruta no encontrada (404). Verifica la configuración del Proxy.");
                    }
                    throw new Error("Credenciales inválidas o error del servidor (" + tokenResponse.status + ")");
                }

                const data = await tokenResponse.json();

                // 4️⃣ Redirigir al endpoint protegido (con barra final)
                window.location.href = `${BASE_PATH}/api/v1/dashboard/`;

            } catch (error) {
                alert("Error en autenticación: " + error.message);
            }
        });
    }

    // JS RECOVERY
    const formRecovery = document.getElementById("forgotPasswordForm");
    if (formRecovery) {
        formRecovery.addEventListener("submit", async function (e) {
            e.preventDefault();
            const email = document.getElementById("email").value;
            const submitBtn = formRecovery.querySelector("button");

            // Feedback visual: Deshabilitar botón
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = "<strong>Enviando...</strong>";

            try {
                const response = await fetch(`${BASE_PATH}/api/v1/users/forgot-password`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ email: email })
                });

                // Verificar si hubo error de sesión/autorización
                if (handleSessionExpiration(response)) return;

                const data = await response.json();

                if (response.ok) {
                    alert(data.message);
                    // Opcional: Redirigir al login
                    window.location.href = `${BASE_PATH}/`;
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
    }

    // JS RESET
    const formReset = document.getElementById("resetPasswordForm");
    // Solo ejecutar lógica de reset si el formulario existe (Evita alertas en Login)
    if (formReset) {
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
                const response = await fetch(`${BASE_PATH}/api/v1/users/reset-password/${token}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ new_password: newPassword })
                });

                // Verificar si el token de reset expiró (401)
                if (handleSessionExpiration(response)) return;

                const data = await response.json();

                if (response.ok) {
                    alert(data.message);
                    window.location.href = `${BASE_PATH}/`; // Redirigir al login
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
    }

});