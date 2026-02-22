// Variables globales para el gráfico y el estado
let metricsChart = null;
let lastUpdateTimestamp = null;
let indicatorTimeout = null;

/**
 * Inicializa el gráfico de métricas y comienza el polling.
 * @param {number} clientId - ID del cliente.
 * @param {Array} labels - Etiquetas iniciales (eje X).
 * @param {Array} cpuData - Datos iniciales de CPU.
 * @param {Array} ramData - Datos iniciales de RAM.
 * @param {Array} diskData - Datos iniciales de Disco.
 */
function initClientMetrics(clientId, labels, cpuData, ramData, diskData) {
    const ctx = document.getElementById('metricsChart').getContext('2d');

    // Configuración del Gráfico
    metricsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'CPU (%)',
                data: cpuData,
                borderColor: 'rgba(244, 67, 54, 1)', // w3-red
                backgroundColor: 'rgba(244, 67, 54, 0.1)',
                fill: true,
                tension: 0.3
            }, {
                label: 'RAM (%)',
                data: ramData,
                borderColor: 'rgba(33, 150, 243, 1)', // w3-blue
                backgroundColor: 'rgba(33, 150, 243, 0.1)',
                fill: true,
                tension: 0.3
            }, {
                label: 'Disk (%)',
                data: diskData,
                borderColor: 'rgba(76, 175, 80, 1)', // w3-green
                backgroundColor: 'rgba(76, 175, 80, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            interaction: { mode: 'index', intersect: false },
            scales: {
                y: { beginAtZero: true, max: 100, title: { display: true, text: 'Porcentaje de Uso' } }
            },
            animation: false // Desactivar animación en actualizaciones para mejor rendimiento
        }
    });

    // Obtener el timestamp inicial del input oculto
    const lastTsInput = document.getElementById('lastTimestamp');
    if (lastTsInput && lastTsInput.value) {
        lastUpdateTimestamp = lastTsInput.value;
    }

    // Iniciar Polling cada 5 segundos
    setInterval(() => fetchNewMetrics(clientId), 5000);
}

/**
 * Consulta nuevas métricas al servidor.
 * @param {number} clientId 
 */
async function fetchNewMetrics(clientId) {
    try {
        let url = `/api/v1/clients/${clientId}/metrics/json`;

        // Agregar parámetro de optimización si tenemos un timestamp previo
        if (lastUpdateTimestamp) {
            url += `?last_timestamp=${encodeURIComponent(lastUpdateTimestamp)}`;
        }

        const response = await fetch(url);
        if (response.ok) {
            const newMetrics = await response.json();

            if (newMetrics.length > 0) {
                // Actualizar el último timestamp conocido
                lastUpdateTimestamp = newMetrics[newMetrics.length - 1].full_timestamp;

                // Mostrar indicador LIVE
                const indicator = document.getElementById('liveIndicator');
                if (indicator) indicator.style.display = 'inline-block';

                // Actualizar datos del gráfico
                newMetrics.forEach(m => {
                    // Agregar nuevos puntos
                    metricsChart.data.labels.push(m.timestamp);
                    metricsChart.data.datasets[0].data.push(m.cpu);
                    metricsChart.data.datasets[1].data.push(m.ram);
                    metricsChart.data.datasets[2].data.push(m.disk);

                    // Mantener ventana de tiempo (eliminar antiguos si hay más de 20)
                    if (metricsChart.data.labels.length > 20) {
                        metricsChart.data.labels.shift();
                        metricsChart.data.datasets.forEach(ds => ds.data.shift());
                    }
                });

                metricsChart.update();

                // Ocultar indicador si no llegan datos en 6 segundos (timeout del polling + margen)
                clearTimeout(indicatorTimeout);
                indicatorTimeout = setTimeout(() => {
                    if (indicator) indicator.style.display = 'none';
                }, 6000);
            }
        }
    } catch (error) {
        console.error("Error fetching metrics:", error);
    }
}