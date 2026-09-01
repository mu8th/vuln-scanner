/** Vulnerability dashboard visualization with Chart.js. */

const app = document.getElementById('app');


async function load_severity_breakdown() {
    const response = await fetch('/severity_breakdown');
    const data = await response.json();

    const ctx = document.getElementById('severity-chart').getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(data.categories),
            datasets: [{
                data: Object.values(data.categories).map(cat => cat.length),
                backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0'],
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Vulnerability Distribution by Category' }
            }
        }
    });

    document.getElementById('severity-chart').nextSibling.textContent = `Total: ${data.total_vulnerabilities} | Average Severity: ${data.average_severity.toFixed(2)}`;
}


async function load_trend_lines() {
    const response = await fetch('/trend_lines');
    const data = await response.json();

    const ctx = document.getElementById('trend-chart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.dates,
            datasets: [
                { label: 'SQL Injection', data: data.sqli_trend, borderColor: '#FF6384', fill: false },
                { label: 'XSS', data: data.xss_trend, borderColor: '#36A2EB', fill: false },
                { label: 'Hardcoded Secrets', data: data.secrets_trend, borderColor: '#FFCE56', fill: false },
                { label: 'Outdated Dependencies', data: data.outdated_deps_trend, borderColor: '#4BC0C0', fill: false },
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Vulnerability Trends Over Time' }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}


async function load_results() {
    const response = await fetch('/results');
    const data = await response.json();

    const tbody = document.querySelector('#results-table tbody');
    tbody.innerHTML = '';

    data.forEach(result => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${result.id}</td><td>${result.category}</td><td>${result.severity_score.toFixed(2)}</td><td>${result.location}</td><td>${result.remediation_suggestion || 'N/A'}</td>`;
        tbody.appendChild(tr);
    });
}


async function load_scans() {
    const response = await fetch('/scans');
    const data = await response.json();

    const ul = document.getElementById('scans-list');
    ul.innerHTML = '';

    if (data.length > 0) {
        data.forEach(scan => {
            const li = document.createElement('li');
            li.textContent = `${scan.target_path} (${scan.severity_score.toFixed(2)})`;
            ul.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = 'No active scans';
        ul.appendChild(li);
    }
}


async function init_dashboard() {
    await load_severity_breakdown();
    await load_trend_lines();
    await load_results();
    await load_scans();
}

init_dashboard();