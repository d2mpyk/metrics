document.addEventListener('DOMContentLoaded', function () {
    const modal = document.getElementById('modalApproved');
    const form = document.getElementById('formApproved');
    const openBtn = document.getElementById('btnOpenModal');
    const closeBtn = document.getElementById('btnCloseModal');

    // Abrir Modal
    if (openBtn) {
        openBtn.onclick = function () {
            modal.style.display = 'block';
        }
    }

    // Cerrar Modal con botón X
    if (closeBtn) {
        closeBtn.onclick = function () {
            modal.style.display = 'none';
        }
    }

    // Cerrar Modal al hacer clic fuera
    window.onclick = function (event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }

    // Manejo del Formulario
    if (form) {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            const formData = new FormData(this);
            const data = Object.fromEntries(formData.entries());

            // Validación simple de formato IPv4
            const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            if (!ipRegex.test(data.ip_address)) {
                alert('Por favor, ingrese una dirección IP válida (ej: 192.168.1.100)');
                return;
            }

            try {
                const response = await fetch('/api/v1/clients/approved', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                if (response.ok) { alert('IP Aprobada correctamente'); location.reload(); }
                else { const err = await response.json(); alert('Error: ' + (err.detail || 'Error desconocido')); }
            } catch (error) {
                console.error('Error:', error); alert('Error de conexión');
            }
        });
    }
});