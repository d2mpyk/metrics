document.getElementById('deviceForm').addEventListener('submit', function (e) {
    const input = this.querySelector('input[name="user_code"]');
    const code = input.value.trim().toUpperCase();

    // Validar formato XXXX-XXXX (Hexadecimal)
    const regex = /^[A-F0-9]{4}-[A-F0-9]{4}$/;

    if (!regex.test(code)) {
        e.preventDefault(); // Detener el envío
        alert("El código debe tener el formato XXXX-XXXX (Ej: A1B2-C3D4).");
    }
    // Si es válido, el formulario se envía normalmente
});