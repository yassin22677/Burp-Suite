// Chart.js setup for Performance Metrics
const ctx = document.getElementById('performanceChart').getContext('2d');
new Chart(ctx, {
    type: 'line',
    data: {
        labels: ['10%', '20%', '40%', '60%', '80%', '100%'],
        datasets: [
            {
                label: 'Low',
                data: [5, 8, 6, 9, 10, 7],
                borderColor: '#007bff',
                tension: 0.3
            },
            {
                label: 'Medium',
                data: [4, 6, 9, 12, 9, 5],
                borderColor: '#28a745',
                tension: 0.3
            },
            {
                label: 'High',
                data: [2, 5, 7, 10, 13, 11],
                borderColor: '#dc3545',
                tension: 0.3
            }
        ]
    },
    options: {
        plugins: { legend: { position: 'bottom' } },
        scales: { y: { beginAtZero: true } }
    }
});

// Circular progress chart for Scan Progress
const progressCtx = document.getElementById('progressChart').getContext('2d');
new Chart(progressCtx, {
    type: 'doughnut',
    data: {
        labels: ['Completed', 'Remaining'],
        datasets: [{
            data: [75, 25],
            backgroundColor: ['#007bff', '#e9ecef'],
            borderWidth: 0
        }]
    },
    options: {
        cutout: '80%',
        plugins: { legend: { display: false } }
    }
});
