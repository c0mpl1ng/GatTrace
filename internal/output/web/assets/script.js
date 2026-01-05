// GatTrace Report JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    loadData();
    initSearch();
});

// Tab switching
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
}

// Load JSON data
async function loadData() {
    try {
        // Load meta data
        const metaResponse = await fetch('meta.json');
        if (metaResponse.ok) {
            const meta = await metaResponse.json();
            document.getElementById('hostname').textContent = `主机: ${meta.hostname || 'Unknown'}`;
            document.getElementById('timestamp').textContent = `采集时间: ${meta.timestamp || 'Unknown'}`;
        }
        
        // Load other data files
        await loadNetworkData();
        await loadProcessData();
        await loadUserData();
        await loadFilesystemData();
        await loadSecurityData();
        await loadPersistenceData();
        await loadSystemData();
        
    } catch (error) {
        console.error('Error loading data:', error);
    }
}

async function loadNetworkData() {
    try {
        const response = await fetch('network.json');
        if (response.ok) {
            const data = await response.json();
            renderNetworkData(data);
        }
    } catch (e) {
        document.getElementById('network-content').innerHTML = '<p>无法加载网络数据</p>';
    }
}

async function loadProcessData() {
    try {
        const response = await fetch('process.json');
        if (response.ok) {
            const data = await response.json();
            renderProcessData(data);
        }
    } catch (e) {
        document.getElementById('process-content').innerHTML = '<p>无法加载进程数据</p>';
    }
}

async function loadUserData() {
    try {
        const response = await fetch('user.json');
        if (response.ok) {
            const data = await response.json();
            renderUserData(data);
        }
    } catch (e) {
        document.getElementById('user-content').innerHTML = '<p>无法加载用户数据</p>';
    }
}

async function loadFilesystemData() {
    try {
        const response = await fetch('filesystem.json');
        if (response.ok) {
            const data = await response.json();
            renderFilesystemData(data);
        }
    } catch (e) {
        document.getElementById('filesystem-content').innerHTML = '<p>无法加载文件系统数据</p>';
    }
}

async function loadSecurityData() {
    try {
        const response = await fetch('security.json');
        if (response.ok) {
            const data = await response.json();
            renderSecurityData(data);
        }
    } catch (e) {
        document.getElementById('security-content').innerHTML = '<p>无法加载安全日志数据</p>';
    }
}

async function loadPersistenceData() {
    try {
        const response = await fetch('persistence.json');
        if (response.ok) {
            const data = await response.json();
            renderPersistenceData(data);
        }
    } catch (e) {
        document.getElementById('persistence-content').innerHTML = '<p>无法加载持久化数据</p>';
    }
}

async function loadSystemData() {
    try {
        const response = await fetch('system.json');
        if (response.ok) {
            const data = await response.json();
            renderSystemData(data);
        }
    } catch (e) {
        document.getElementById('system-content').innerHTML = '<p>无法加载系统数据</p>';
    }
}

// Render functions
function renderNetworkData(data) {
    let html = '<h3>网络连接</h3>';
    if (data.connections && data.connections.length > 0) {
        html += '<table id="network-table"><thead><tr>';
        html += '<th>协议</th><th>本地地址</th><th>远程地址</th><th>状态</th><th>PID</th>';
        html += '</tr></thead><tbody>';
        data.connections.forEach(conn => {
            html += `<tr>
                <td>${conn.protocol || '-'}</td>
                <td>${conn.local_address || '-'}</td>
                <td>${conn.remote_address || '-'}</td>
                <td>${conn.status || '-'}</td>
                <td><a class="pid-link" onclick="jumpToProcess(${conn.pid})">${conn.pid || '-'}</a></td>
            </tr>`;
        });
        html += '</tbody></table>';
    } else {
        html += '<p>无网络连接数据</p>';
    }
    document.getElementById('network-content').innerHTML = html;
}

function renderProcessData(data) {
    let html = '<table id="process-table"><thead><tr>';
    html += '<th>PID</th><th>名称</th><th>命令行</th><th>用户</th><th>CPU%</th><th>内存%</th>';
    html += '</tr></thead><tbody>';
    
    const processes = data.processes || data || [];
    processes.forEach(proc => {
        html += `<tr data-pid="${proc.pid}">
            <td>${proc.pid || '-'}</td>
            <td>${proc.name || '-'}</td>
            <td title="${proc.cmdline || ''}">${truncate(proc.cmdline || proc.exe || '-', 50)}</td>
            <td>${proc.username || '-'}</td>
            <td>${(proc.cpu_percent || 0).toFixed(1)}</td>
            <td>${(proc.memory_percent || 0).toFixed(1)}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    document.getElementById('process-content').innerHTML = html;
}

function renderUserData(data) {
    let html = '<h3>当前用户</h3>';
    if (data.current_user) {
        html += `<p><strong>用户名:</strong> ${data.current_user.username || '-'}</p>`;
        html += `<p><strong>UID:</strong> ${data.current_user.uid || '-'}</p>`;
    }
    
    if (data.logged_in_users && data.logged_in_users.length > 0) {
        html += '<h3>登录用户</h3><table><thead><tr>';
        html += '<th>用户名</th><th>终端</th><th>主机</th><th>登录时间</th>';
        html += '</tr></thead><tbody>';
        data.logged_in_users.forEach(user => {
            html += `<tr>
                <td>${user.username || '-'}</td>
                <td>${user.terminal || '-'}</td>
                <td>${user.host || '-'}</td>
                <td>${user.login_time || '-'}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    }
    document.getElementById('user-content').innerHTML = html;
}

function renderFilesystemData(data) {
    let html = '<table id="filesystem-table"><thead><tr>';
    html += '<th>路径</th><th>大小</th><th>修改时间</th><th>权限</th>';
    html += '</tr></thead><tbody>';
    
    const files = data.recent_files || data.files || [];
    files.forEach(file => {
        html += `<tr>
            <td title="${file.path || ''}">${truncate(file.path || '-', 60)}</td>
            <td>${formatSize(file.size || 0)}</td>
            <td>${file.modified_time || '-'}</td>
            <td>${file.permissions || '-'}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    document.getElementById('filesystem-content').innerHTML = html;
}

function renderSecurityData(data) {
    let html = '<table id="security-table"><thead><tr>';
    html += '<th>时间</th><th>来源</th><th>事件ID</th><th>级别</th><th>描述</th>';
    html += '</tr></thead><tbody>';
    
    const logs = data.logs || data.events || [];
    logs.forEach(log => {
        html += `<tr>
            <td>${log.timestamp || log.time || '-'}</td>
            <td>${log.source || log.provider || '-'}</td>
            <td>${log.event_id || '-'}</td>
            <td><span class="status-badge ${getLevelClass(log.level)}">${log.level || '-'}</span></td>
            <td title="${log.message || ''}">${truncate(log.message || log.description || '-', 80)}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    document.getElementById('security-content').innerHTML = html;
}

function renderPersistenceData(data) {
    let html = '';
    
    if (data.services && data.services.length > 0) {
        html += '<h3>服务</h3><table><thead><tr>';
        html += '<th>名称</th><th>状态</th><th>启动类型</th><th>路径</th>';
        html += '</tr></thead><tbody>';
        data.services.forEach(svc => {
            html += `<tr>
                <td>${svc.name || '-'}</td>
                <td>${svc.status || '-'}</td>
                <td>${svc.start_type || '-'}</td>
                <td>${truncate(svc.path || '-', 50)}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    }
    
    if (data.scheduled_tasks && data.scheduled_tasks.length > 0) {
        html += '<h3>计划任务</h3><table><thead><tr>';
        html += '<th>名称</th><th>状态</th><th>下次运行</th><th>命令</th>';
        html += '</tr></thead><tbody>';
        data.scheduled_tasks.forEach(task => {
            html += `<tr>
                <td>${task.name || '-'}</td>
                <td>${task.status || '-'}</td>
                <td>${task.next_run || '-'}</td>
                <td>${truncate(task.command || '-', 50)}</td>
            </tr>`;
        });
        html += '</tbody></table>';
    }
    
    document.getElementById('persistence-content').innerHTML = html || '<p>无持久化数据</p>';
}

function renderSystemData(data) {
    let html = '<div class="system-info">';
    html += `<p><strong>操作系统:</strong> ${data.os || '-'}</p>`;
    html += `<p><strong>内核版本:</strong> ${data.kernel || '-'}</p>`;
    html += `<p><strong>启动时间:</strong> ${data.boot_time || '-'}</p>`;
    html += `<p><strong>运行时间:</strong> ${data.uptime || '-'}</p>`;
    html += '</div>';
    document.getElementById('system-content').innerHTML = html;
}

// Search functionality
function initSearch() {
    const searchInputs = document.querySelectorAll('.search-box input');
    searchInputs.forEach(input => {
        input.addEventListener('input', function() {
            const tableId = this.id.replace('-search', '-table');
            const table = document.getElementById(tableId);
            if (table) {
                filterTable(table, this.value);
            }
        });
    });
}

function filterTable(table, query) {
    const rows = table.querySelectorAll('tbody tr');
    const lowerQuery = query.toLowerCase();
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(lowerQuery) ? '' : 'none';
    });
}

// Utility functions
function truncate(str, len) {
    if (!str) return '-';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getLevelClass(level) {
    if (!level) return '';
    const l = level.toLowerCase();
    if (l.includes('error') || l.includes('critical')) return 'status-danger';
    if (l.includes('warning') || l.includes('warn')) return 'status-warning';
    return 'status-success';
}

function jumpToProcess(pid) {
    // Switch to process tab
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    document.querySelector('[data-tab="process"]').classList.add('active');
    document.getElementById('process').classList.add('active');
    
    // Highlight the process row
    const row = document.querySelector(`tr[data-pid="${pid}"]`);
    if (row) {
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.style.background = '#fef3c7';
        setTimeout(() => {
            row.style.background = '';
        }, 2000);
    }
}
