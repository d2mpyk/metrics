from fastapi.templating import Jinja2Templates

# Apunta al directorio donde están tus templates
templates = Jinja2Templates(directory="templates")


def test_email_confirmation_template_render():
    """
    Verifica que el template 'email_confirmation.html' se renderice
    correctamente con las variables de contexto.
    """
    # 1. Definir el contexto de prueba
    context = {"user": "TestUser", "url": "http://example.com/verify/some_fake_token"}

    # 2. Cargar y renderizar el template
    template = templates.get_template("email/email_confirmation.html")
    html_content = template.render(context)

    # 3. Verificar que las variables de contexto están en el HTML renderizado
    assert "Hola <strong>TestUser</strong>," in html_content
    assert 'href="http://example.com/verify/some_fake_token"' in html_content
    assert ">Confirmar Cuenta</a>" in html_content
