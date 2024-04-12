# Cleopatra Password Manager
Proyecto de Gestión de Contraseñas y Seguridad en Flask
Aplicación web desarrollada con Python y Flask que permite a los usuarios almacenar de forma segura sus contraseñas y gestionar sus cuentas. Está diseñado con un enfoque centrado en la seguridad y utiliza diversas técnicas y políticas para proteger la información confidencial de los usuarios.

## Tecnologías Utilizadas:
- **Lenguaje de Programación:** Python
- **Framework Web:** Flask
- **Base de Datos:** SQLite3
- **Seguridad:** Bcrypt, CSRF Protection, Validación de Entrada, Gestión de Sesiones por Tokens, Seguridad de las Cookies, IAM RBAC, DLP, Prevención contra Fuerza Bruta con bloqueo de cuenta.

## Funcionalidades Destacadas:
- **Autenticación Segura:** Implementación de Bcrypt para el cifrado de contraseñas, incluyendo la adición de salt para una mayor seguridad.
- **Prevención de Ataques:** Validación de entrada para prevenir ataques de inyección SQL y cross-site scripting (XSS).
- **Prevención contra Fuerza Bruta:** Bloqueo de cuenta luego de X intentos fallidos (Rol admin puede desbloquear cuenta).
- **Control de Acceso:** Gestión de roles de usuario y administrador (IAM) para garantizar la seguridad y la privacidad de los datos.
- **Protección CSRF:** Implementación de tokens CSRF en formularios para prevenir ataques de falsificación de solicitudes entre sitios.
- **Políticas de Contraseña Seguras:** Implementación de políticas de contraseña seguras para garantizar contraseñas robustas y difíciles de adivinar.
- **Gestión de Sesiones:** Utilización de tokens de autenticación y sesiones seguras para mantener la autenticación del usuario de manera segura.
- **Seguridad de las Cookies:** Configuración de cookies seguras para proteger la integridad y la confidencialidad de los datos del usuario.

## Password Manager:
Además de las medidas de seguridad mencionadas, el proyecto tiene un administrador de contraseñas que permite a los usuarios almacenar y gestionar sus credenciales de inicio de sesión de forma segura. Los usuarios pueden agregar, editar y eliminar contraseñas para diversas aplicaciones y servicios, asegurando un almacenamiento seguro y accesible de sus datos sensibles.
