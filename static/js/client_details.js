// Variables globales para el gráfico y el estado
let metricsChart = null;
let networkChart = null;
let lastUpdateTimestamp = null;
let indicatorTimeout = null;

/**
 * Inicializa el gráfico de métricas y comienza el polling.
 * @param {number} clientId - ID del cliente.
 * @param {Array} labels - Etiquetas iniciales (eje X).
 * @param {Array} cpuData - Datos iniciales de CPU.
 * @param {Array} ramData - Datos iniciales de RAM.
 * @param {Array} diskData - Datos iniciales de Disco.
 * @param {Array} netSentData - Datos iniciales de Red Enviados (KB/s).
 * @param {Array} netRecvData - Datos iniciales de Red Recibidos (KB/s).
 */
function initClientMetrics(clientId, labels, cpuData, ramData, diskData, netSentData, netRecvData) {
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

    // Configuración del Gráfico de Red
    const ctxNet = document.getElementById('networkChart').getContext('2d');
    networkChart = new Chart(ctxNet, {
        type: 'line',
        data: {
            labels: labels, // Comparten las mismas etiquetas de tiempo
            datasets: [{
                label: 'Enviado (KB/s)',
                data: netSentData,
                borderColor: 'rgba(255, 152, 0, 1)', // Orange
                backgroundColor: 'rgba(255, 152, 0, 0.1)',
                fill: true,
                tension: 0.3
            }, {
                label: 'Recibido (KB/s)',
                data: netRecvData,
                borderColor: 'rgba(156, 39, 176, 1)', // Purple
                backgroundColor: 'rgba(156, 39, 176, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            interaction: { mode: 'index', intersect: false },
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Velocidad (KB/s)' } }
            },
            animation: false
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
    const statusLabel = document.getElementById('metricStatus');
    try {
        const BASE_PATH = document.body.getAttribute("data-root-path") || "";
        let url = `${BASE_PATH}/api/v1/clients/${clientId}/metrics/json`;

        // Agregar parámetro de optimización si tenemos un timestamp previo
        if (lastUpdateTimestamp) {
            url += `?last_timestamp=${encodeURIComponent(lastUpdateTimestamp)}`;
        }

        const response = await fetch(url);
        if (response.ok) {
            const newMetrics = await response.json();

            if (newMetrics.length > 0) {
                if (statusLabel) {
                    statusLabel.textContent = "Recibiendo";
                    statusLabel.className = "w3-tag w3-teal w3-round";
                }

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

                    // Agregar datos al gráfico de red
                    networkChart.data.labels.push(m.timestamp);
                    networkChart.data.datasets[0].data.push(m.net_speed_sent_kbytes_s);
                    networkChart.data.datasets[1].data.push(m.net_speed_recv_kbytes_s);

                    // Mantener ventana de tiempo (eliminar antiguos si hay más de 20)
                    if (metricsChart.data.labels.length > 20) {
                        metricsChart.data.labels.shift();
                        metricsChart.data.datasets.forEach(ds => ds.data.shift());

                        networkChart.data.labels.shift();
                        networkChart.data.datasets.forEach(ds => ds.data.shift());
                    }
                });

                metricsChart.update();
                networkChart.update();

                // Ocultar indicador si no llegan datos en 6 segundos (timeout del polling + margen)
                clearTimeout(indicatorTimeout);
                indicatorTimeout = setTimeout(() => {
                    if (indicator) indicator.style.display = 'none';
                }, 6000);
            }
        } else {
            if (statusLabel) {
                statusLabel.textContent = "Error";
                statusLabel.className = "w3-tag w3-red w3-round";
            }
        }
    } catch (error) {
        console.error("Error fetching metrics:", error);
        if (statusLabel) {
            statusLabel.textContent = "Error";
            statusLabel.className = "w3-tag w3-red w3-round";
        }
    }
}