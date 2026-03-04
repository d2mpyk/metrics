# WISE Management Server

## 1. Descripción General

WISE Management Server es una aplicación backend construida con **FastAPI** diseñada para la gestión y monitorización remota de dispositivos (clientes). Permite registrar dispositivos de forma segura, recolectar métricas de rendimiento en tiempo real y visualizarlas a través de un panel de administración web.

### Características Principales
*   **Dashboard de Administración:** Interfaz web para administradores (creada con Jinja2) para ver y gestionar dispositivos.
*   **Flujo de Autorización de Dispositivos:** Un sistema seguro (inspirado en OAuth 2.0 Device Flow) para registrar nuevos dispositivos sin exponer credenciales sensibles.
*   **Recolección de Métricas Encriptadas:** Los dispositivos reportan métricas (CPU, RAM, Disco, Red) que son encriptadas en el cliente y desencriptadas en el servidor para garantizar la confidencialidad.
*   **Cálculo de Velocidad de Red:** El servidor calcula la velocidad de transferencia de red (subida/bajada) en tiempo real basándose en los contadores acumulativos que envía el cliente.
*   **Autenticación Robusta:** Sistema de roles (admin/user) con autenticación basada en JWT, compatible tanto con cookies `HttpOnly` para el navegador como con `Authorization: Bearer` para otros clientes.

## 2. Funcionamiento Técnico

### Arquitectura
*   **Backend:** Python con FastAPI.
*   **Base de Datos:** SQLAlchemy ORM, permitiendo flexibilidad con bases de datos como PostgreSQL, MySQL o SQLite.
*   **Frontend (Dashboard):** Renderizado del lado del servidor con plantillas Jinja2.
*   **Criptografía:** Librería `cryptography` para encriptación AES-CBC de las métricas.
*   **Autenticación:** PyJWT para tokens y Argon2 para el hash de contraseñas.

### Flujo de Autorización de un Dispositivo

El registro de un nuevo dispositivo es un proceso de varios pasos para garantizar la seguridad:

1.  **Aprobación de IP (Admin):** Un administrador debe registrar y describir la dirección IP del dispositivo que se va a conectar desde el dashboard (`/clients/approved`).
2.  **Solicitud de Código (Dispositivo):** El dispositivo (desde la IP aprobada) hace una petición a `/api/v1/auth/device/code`. El servidor genera y devuelve un `user_code` (corto, para el humano) y un `device_code` (largo, para la máquina).
3.  **Activación (Admin):** El administrador introduce el `user_code` en la página de activación del dashboard. El servidor verifica el código y marca el `device_code` asociado como "verificado".
4.  **Obtención de Token (Dispositivo):** El dispositivo comienza a hacer "polling" (peticiones periódicas) al endpoint `/api/v1/auth/device/token`, enviando su `device_code`.
5.  **Registro Exitoso:** Una vez que el admin ha verificado el código, la siguiente petición de polling del dispositivo tiene éxito. El servidor crea una entrada para el nuevo cliente en la base de datos y le devuelve:
    *   Un `access_token` de larga duración (válido hasta fin de año).
    *   Una `client_secret_key` única y secreta.

### Flujo de Envío de Métricas

1.  **Encriptación (Dispositivo):** El dispositivo recolecta sus métricas (CPU, RAM, Disco, y los contadores **acumulativos** de red `net_sent` y `net_recv`).
2.  El payload de métricas se encripta usando **AES-CBC**. La clave de encriptación se deriva de la `client_secret_key` obtenida durante el registro.
3.  **Envío (Dispositivo):** El dispositivo envía el payload encriptado a `/api/v1/clients/metrics`, autenticándose con su `access_token` en la cabecera `Authorization`.
4.  **Procesamiento (Servidor):**
    *   El servidor valida el `access_token` y obtiene la identidad del cliente.
    *   Usa la `client_secret_key` del cliente (almacenada en la DB) para desencriptar el payload.
    *   Compara los valores `net_sent` y `net_recv` con la última métrica recibida para calcular el delta (la cantidad de datos transferidos desde el último reporte) y lo divide por el tiempo transcurrido para obtener la velocidad de red (Bytes/segundo).
    *   Almacena la nueva métrica, incluyendo la velocidad calculada, en la base de datos.

## 3. Guía de Uso Rápido

Sigue estos pasos para poner en marcha el servidor y simular un cliente.

### a. Configuración del Servidor

1.  **Clonar el repositorio y navegar a la carpeta `SERVER`.**
2.  **Crear un entorno virtual e instalar dependencias:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # En Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```
3.  **Configurar variables de entorno:**
    *   Copia el archivo `.env_example` a `.env`.
    *   Edita el archivo `.env` y establece, como mínimo, una `SECRET_KEY` segura. Puedes generar una con `python -c 'import secrets; print(secrets.token_hex(32))'`.
4.  **Ejecutar el servidor:**
    ```bash
    uvicorn app.main:app --reload
    ```
    El servidor estará disponible en `http://localhost:8000`.

### b. Simulación de un Cliente

El script `simulate_client.py` realiza el flujo completo de un dispositivo, desde el registro hasta el envío continuo de métricas.

1.  **Crear un administrador:** (Al inicio de la App se crea un administrador con los datos (ADMIN y NAME) del archivo de variables de entorno (.env), la clave inicial es: admin, se puede cambiar en el dashboard una vez logeado.).
2.  **Aprobar la IP del cliente:**
    *   Abre `http://localhost:8000` en tu navegador e inicia sesión como admin.
    *   Ve a la sección "IPs Aprobadas" (`/api/v1/clients/approved`).
    *   Añade la IP `127.0.0.1` con una descripción (ej: "Mi PC Local").
3.  **Ejecutar el script de simulación:**
    *   Abre una **nueva terminal**.
    *   Navega a la carpeta `SERVER` y ejecuta el script:
    ```bash
    python simulate_client.py
    ```
4.  **Autorizar el dispositivo:**
    *   El script te mostrará una URL de verificación y un `user_code`.
    *   Copia el `user_code`, ve a la URL en tu navegador (donde tienes la sesión de admin iniciada) y pégalo para activar el dispositivo.
5.  **Monitorizar:**
    *   El script confirmará la autorización y comenzará a enviar métricas aleatorias cada 5 segundos.
    *   Vuelve al dashboard, ve a "Gestión de Dispositivos", y verás tu nuevo cliente. Haz clic en él para ver sus métricas actualizándose en tiempo real.