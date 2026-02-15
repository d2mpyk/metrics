# FastAPI Template
### Este es un template inicial de app con user model y auth funcional
### Usa Cookies HttpOnly y Middleware para proteger Html's
* Endpoints:
    * /api/v1/users - Muestra todos los usuarios
    * /api/v1/users/approved - Muestra todos los usuarios aprobados
    * /api/v1/users/approved/EMAIL - Agrega un usuario a la lista de Aprobados
    * /api/v1/users/create - Crea un usuario
        * Solo crea usuarios contenidos en la tabla approved
    * /api/v1/users/token - Login para acceso de usuarios
    * /api/v1/users/verify/TOKEN - Verifica el Email del usuario
    * /api/v1/users/me - Muestra el usuario actual
    * /api/v1/users/ID - Muestra, Edita y Elimina el usuario por id
        * Endpoint's restringido solo para usuario admin

* Librerias:
    * Argon2 - Para Hash Password
    * PyJWT - Para los Tokens
    * Pydantic - Para los modelos de la APP
    * SqlAlchemy - Para ORM de Base de Datos

* Consideraciones: 
    * Crear un archivo .env para las variables de entorno
    * Ejemplo disponible .env_example
    * Editar ruta de .env en el archivo utils/config.py

    