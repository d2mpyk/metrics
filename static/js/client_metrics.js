function initializeMetricsCharts(clientId) {
    let lastTimestamp = null;
    let metricsInterval = null;
    let currentRange = 'live';

    const resourceCtx = document.getElementById('resourceChart').getContext('2d');
    const networkCtx = document.getElementById('networkChart').getContext('2d');

    const resourceChart = new Chart(resourceCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'CPU (%)', data: [], borderColor: 'rgba(255, 99, 132, 1)', backgroundColor: 'rgba(255, 99, 132, 0.2)', fill: false, tension: 0.1 },
                { label: 'RAM (%)', data: [], borderColor: 'rgba(54, 162, 235, 1)', backgroundColor: 'rgba(54, 162, 235, 0.2)', fill: false, tension: 0.1 },
                { label: 'Disco (%)', data: [], borderColor: 'rgba(75, 192, 192, 1)', backgroundColor: 'rgba(75, 192, 192, 0.2)', fill: false, tension: 0.1 }
            ]
        },
        options: { scales: { y: { beginAtZero: true, max: 100 } }, animation: { duration: 500 } }
    });

    const networkChart = new Chart(networkCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'Enviado (KB/s)', data: [], borderColor: 'rgba(255, 159, 64, 1)', backgroundColor: 'rgba(255, 159, 64, 0.2)', fill: false, tension: 0.1 },
                { label: 'Recibido (KB/s)', data: [], borderColor: 'rgba(153, 102, 255, 1)', backgroundColor: 'rgba(153, 102, 255, 0.2)', fill: false, tension: 0.1 }
            ]
        },
        options: { scales: { y: { beginAtZero: true } }, animation: { duration: 500 } }
    });

    function updateCharts(metrics, isAppend) {
        // Si estamos en modo histórico (no append), permitimos muchos puntos.
        // Si es en vivo, limitamos a 30 para que se mueva.
        const maxDataPoints = currentRange === 'live' ? 30 : 10000;

        if (!isAppend) {
            [resourceChart, networkChart].forEach(chart => {
                chart.data.labels = [];
                chart.data.datasets.forEach(ds => ds.data = []);
            });
        }

        metrics.forEach(metric => {
            // Agregar etiquetas (timestamp)
            [resourceChart, networkChart].forEach(chart => {
                chart.data.labels.push(metric.timestamp);
                if (chart.data.labels.length > maxDataPoints) {
                    chart.data.labels.shift();
                }
            });

            // Agregar datos
            resourceChart.data.datasets[0].data.push(metric.cpu);
            resourceChart.data.datasets[1].data.push(metric.ram);
            resourceChart.data.datasets[2].data.push(metric.disk);

            networkChart.data.datasets[0].data.push(metric.net_speed_sent_kbytes_s);
            networkChart.data.datasets[1].data.push(metric.net_speed_recv_kbytes_s);

            // Limpiar datos antiguos si excede el límite
            [resourceChart, networkChart].forEach(chart => {
                chart.data.datasets.forEach(ds => {
                    if (ds.data.length > maxDataPoints) {
                        ds.data.shift();
                    }
                });
            });
        });

        resourceChart.update();
        networkChart.update();
    }

    async function fetchMetrics() {
        const BASE_PATH = document.body.getAttribute("data-root-path") || "";
        let url = `${BASE_PATH}/api/v1/clients/${clientId}/metrics/json`;

        if (currentRange !== 'live') {
            url += `?time_range=${currentRange}`;
        } else if (lastTimestamp) {
            url += `?last_timestamp=${lastTimestamp}`;
        }

        try {
            const response = await fetch(url);
            if (!response.ok) { console.error('Error fetching metrics:', response.statusText); return; }
            const metrics = await response.json();

            if (metrics.length > 0) {
                const isAppend = (currentRange === 'live' && lastTimestamp !== null);
                updateCharts(metrics, isAppend);
                lastTimestamp = metrics[metrics.length - 1].full_timestamp;
            } else if (currentRange !== 'live') {
                updateCharts([], false); // Limpiar si no hay datos en el rango
            }
        } catch (error) { console.error('Failed to fetch metrics:', error); }
    }

    window.changeTimeRange = function (range, btn) {
        // Actualizar UI de botones
        document.querySelectorAll('.time-range-btn').forEach(b => {
            b.classList.remove('w3-blue');
            b.classList.add('w3-white');
        });
        if (btn) { btn.classList.remove('w3-white'); btn.classList.add('w3-blue'); }

        currentRange = range;
        lastTimestamp = null;
        if (metricsInterval) clearInterval(metricsInterval);

        if (range === 'live') {
            updateCharts([], false);
            fetchMetrics();
            metricsInterval = setInterval(fetchMetrics, 5000);
        } else {
            fetchMetrics();
        }
    };

    fetchMetrics();
    metricsInterval = setInterval(fetchMetrics, 5000);
}