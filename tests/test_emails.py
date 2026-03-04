from fastapi import status
from unittest.mock import patch, MagicMock
from utils.auth import _send_email

# -----------------------------------------------------------------------------
# TESTS DE RUTAS DE VISTA PREVIA (DEV)
# -----------------------------------------------------------------------------


def test_preview_email_confirmation_route(client):
    """Verifica que la ruta de vista previa de confirmación cargue correctamente."""
    response = client.get("/dev/preview/email-confirmation")
    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]
    assert "Confirmación de Correo" in response.text
    assert "UsuarioDePrueba" in response.text


def test_preview_password_reset_route(client):
    """Verifica que la ruta de vista previa de reseteo de password cargue correctamente."""
    response = client.get("/dev/preview/password-reset")
    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]
    assert "Restablecer Contraseña" in response.text
    assert "test@example.com" in response.text


# -----------------------------------------------------------------------------
# TESTS DE LÓGICA DE ENVÍO DE CORREO (SMTP)
# -----------------------------------------------------------------------------


@patch("smtplib.SMTP_SSL")
def test_send_email_logic(mock_smtp):
    """
    Verifica que la función interna _send_email intente conectar al servidor SMTP
    y enviar el mensaje correctamente.
    """
    # Configurar el mock del servidor SMTP para soportar el contexto 'with'
    mock_server = MagicMock()
    mock_smtp.return_value.__enter__.return_value = mock_server

    # Datos de prueba
    recipient = "destinatario@example.com"
    subject = "Asunto de Prueba"
    html_content = "<h1>Hola Mundo</h1>"

    # Ejecutar la función
    _send_email(recipient, subject, html_content)

    # Verificaciones
    mock_smtp.assert_called_once()  # Se instanció la conexión SSL
    mock_server.login.assert_called_once()  # Se intentó hacer login
    mock_server.sendmail.assert_called_once()  # Se intentó enviar el correo

    # Verificar que los argumentos pasados a sendmail sean correctos
    args, _ = mock_server.sendmail.call_args
    # args[0] es el remitente (desde settings), args[1] es el destinatario
    assert args[1] == recipient
    # args[2] es el mensaje como string, debe contener el asunto y el HTML
    message_str = args[2]
    assert f"Subject: {subject}" in message_str
    assert html_content in message_str
