// Основные переменные
let statsInterval;
let chartConnections;
let chartTraffic;

// Форматирование данных
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatTime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

// Обновление статуса сервера
async function updateServerStatus() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();

        // Статус сервера
        const statusIndicator = document.getElementById('serverStatus');
        const statusDot = statusIndicator.querySelector('.status-dot');
        const statusText = statusIndicator.querySelector('.status-text');

        if (stats.status === 'running') {
            statusDot.className = 'status-dot online';
            statusText.textContent = 'В работе';
            document.getElementById('startBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
        } else {
            statusDot.className = 'status-dot offline';
            statusText.textContent = 'Остановлен';
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
        }

        // Обновление статистики
        document.getElementById('currentConnections').textContent = stats.current_connections;
        document.getElementById('totalConnections').textContent = stats.total_connections;
        document.getElementById('uploadData').textContent = formatBytes(stats.total_data.upload);
        document.getElementById('downloadData').textContent = formatBytes(stats.total_data.download);

        // Обновление списка активных пользователей
        const activeUsersList = document.getElementById('activeUsersList');
        if (stats.active_users.length > 0) {
            activeUsersList.innerHTML = stats.active_users.map(user =>
                `<div class="user-tag">${user}</div>`
            ).join('');
        } else {
            activeUsersList.innerHTML = '<p>Нет активных подключений</p>';
        }

        // Обновление графиков
        updateCharts(stats);

        // Обновление таблицы клиентов
        updateClientsTable();

    } catch (error) {
        console.error('Error updating status:', error);
    }
}

// Обновление таблицы клиентов
async function updateClientsTable() {
    try {
        const response = await fetch('/api/users');
        const users = await response.json();

        const tableBody = document.getElementById('clientsBody');
        tableBody.innerHTML = '';

        users.forEach(user => {
            if (user.connected) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${user.username}</td>
                    <td>${user.client_ip || 'N/A'}</td>
                    <td><span class="status-badge online">Online</span></td>
                    <td>${formatBytes(user.data_usage.upload)}</td>
                    <td>${formatBytes(user.data_usage.download)}</td>
                    <td>
                        <button onclick="kickUser('${user.username}')" class="btn-sm btn-danger">Отключить</button>
                    </td>
                `;
                tableBody.appendChild(row);
            }
        });

        // Обновление таблицы пользователей (админ)
        if (document.getElementById('usersBody')) {
            updateUsersTable(users);
        }

    } catch (error) {
        console.error('Error updating clients:', error);
    }
}

// Обновление таблицы пользователей
function updateUsersTable(users) {
    const tableBody = document.getElementById('usersBody');
    tableBody.innerHTML = '';

    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.username}</td>
            <td>${new Date(user.created_at).toLocaleDateString()}</td>
            <td>${user.last_connection ? new Date(user.last_connection).toLocaleString() : 'Никогда'}</td>
            <td><span class="status-badge ${user.connected ? 'online' : 'offline'}">
                ${user.connected ? 'Online' : 'Offline'}
            </span></td>
            <td>${formatBytes(user.data_usage.upload + user.data_usage.download)}</td>
            <td>
                ${user.username !== 'admin' ? `
                    <button onclick="deleteUser('${user.username}')" class="btn-sm btn-danger">Удалить</button>
                ` : 'Администратор'}
            </td>
        `;
        tableBody.appendChild(row);
    });
}

// Управление графиками
function updateCharts(stats) {
    if (!chartConnections) {
        initCharts();
    }

    // Обновление данных графиков
    chartConnections.data.datasets[0].data.push(stats.current_connections);
    if (chartConnections.data.datasets[0].data.length > 20) {
        chartConnections.data.datasets[0].data.shift();
    }
    chartConnections.update('none');

    chartTraffic.data.datasets[0].data.push(stats.total_data.upload / 1024 / 1024);
    chartTraffic.data.datasets[1].data.push(stats.total_data.download / 1024 / 1024);

    if (chartTraffic.data.datasets[0].data.length > 20) {
        chartTraffic.data.datasets[0].data.shift();
        chartTraffic.data.datasets[1].data.shift();
    }
    chartTraffic.update('none');
}

function initCharts() {
    const ctxConnections = document.getElementById('connectionsChart').getContext('2d');
    chartConnections = new Chart(ctxConnections, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                label: 'Активные подключения',
                data: [],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });

    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    chartTraffic = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [
                {
                    label: 'Отправлено (MB)',
                    data: [],
                    borderColor: '#2ecc71',
                    backgroundColor: 'rgba(46, 204, 113, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Получено (MB)',
                    data: [],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// API функции
async function startVPNServer() {
    try {
        const response = await fetch('/api/start_vpn', {
            method: 'POST'
        });
        const result = await response.json();

        if (response.ok) {
            alert('VPN сервер запущен');
            updateServerStatus();
        } else {
            alert('Ошибка: ' + result.error);
        }
    } catch (error) {
        alert('Ошибка сети: ' + error.message);
    }
}

async function stopVPNServer() {
    if (!confirm('Вы уверены, что хотите остановить VPN сервер?')) return;

    try {
        const response = await fetch('/api/stop_vpn', {
            method: 'POST'
        });
        const result = await response.json();

        if (response.ok) {
            alert('VPN сервер остановлен');
            updateServerStatus();
        } else {
            alert('Ошибка: ' + result.error);
        }
    } catch (error) {
        alert('Ошибка сети: ' + error.message);
    }
}

async function addUser() {
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;

    if (!username || !password) {
        alert('Заполните все поля');
        return;
    }

    try {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();

        if (response.ok) {
            alert('Пользователь добавлен');
            updateServerStatus();
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
        } else {
            alert('Ошибка: ' + result.error);
        }
    } catch (error) {
        alert('Ошибка сети: ' + error.message);
    }
}

async function deleteUser(username) {
    if (!confirm(`Удалить пользователя ${username}?`)) return;

    try {
        const response = await fetch(`/api/users?username=${encodeURIComponent(username)}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (response.ok) {
            alert('Пользователь удален');
            updateServerStatus();
        } else {
            alert('Ошибка: ' + result.error);
        }
    } catch (error) {
        alert('Ошибка сети: ' + error.message);
    }
}

async function kickUser(username) {
    if (!confirm(`Отключить пользователя ${username}?`)) return;

    try {
        const response = await fetch('/api/kick_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });

        const result = await response.json();

        if (response.ok) {
            alert('Пользователь отключен');
            updateServerStatus();
        } else {
            alert('Ошибка: ' + result.error);
        }
    } catch (error) {
        alert('Ошибка сети: ' + error.message);
    }
}

async function updateLogs() {
    try {
        // В реальном проекте здесь был бы запрос к API логов
        const logsElement = document.getElementById('serverLogs');
        logsElement.textContent = 'Логи обновлены: ' + new Date().toLocaleTimeString();
    } catch (error) {
        console.error('Error updating logs:', error);
    }
}

// Навигация по разделам
function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-menu a');
    const sections = document.querySelectorAll('.content-section');

    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();

            const targetId = this.getAttribute('href').substring(1);

            // Обновление активного пункта меню
            navLinks.forEach(l => l.parentElement.classList.remove('active'));
            this.parentElement.classList.add('active');

            // Показать выбранный раздел
            sections.forEach(section => {
                section.classList.remove('active');
                if (section.id === targetId) {
                    section.classList.add('active');
                }
            });
        });
    });
}

// Инициализация
document.addEventListener('DOMContentLoaded', function() {
    // Настройка навигации
    setupNavigation();

    // Кнопки управления
    document.getElementById('startBtn').addEventListener('click', startVPNServer);
    document.getElementById('stopBtn').addEventListener('click', stopVPNServer);

    // Кнопка добавления пользователя
    if (document.getElementById('addUserBtn')) {
        document.getElementById('addUserBtn').addEventListener('click', addUser);
    }

    // Кнопка обновления логов
    document.getElementById('refreshLogs').addEventListener('click', updateLogs);

    // Обновление статуса каждые 5 секунд
    updateServerStatus();
    statsInterval = setInterval(updateServerStatus, 5000);

    // Инициализация графиков
    initCharts();
});

// Очистка при закрытии
window.addEventListener('beforeunload', function() {
    if (statsInterval) {
        clearInterval(statsInterval);
    }
});