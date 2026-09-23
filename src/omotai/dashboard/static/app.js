document.addEventListener('DOMContentLoaded', () => {
    // Admin login: any 401 from the API (except the login call itself) shows the token prompt.
    const loginOverlay = document.getElementById('login-overlay');
    const rawFetch = window.fetch.bind(window);
    window.fetch = async (...args) => {
        const res = await rawFetch(...args);
        if (res.status === 401 && !String(args[0]).startsWith('/api/login')) {
            loginOverlay.style.display = 'flex';
        }
        return res;
    };
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({token: document.getElementById('login-token').value})
        });
        if (res.ok) {
            location.reload();
        } else {
            document.getElementById('login-error').textContent = 'Invalid token';
        }
    });
    fetch('/api/me');

    // Navigation
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = item.getAttribute('data-target');
            
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            viewSections.forEach(v => {
                if(v.id === targetId) {
                    v.classList.add('active');
                } else {
                    v.classList.remove('active');
                }
            });

            if (targetId === 'agents-view') loadAgents();
            if (targetId === 'secrets-view') loadSecrets();
            if (targetId === 'approvals-view') loadApprovals();
        });
    });

    // Agents API
    const btnCreateAgent = document.getElementById('btn-create-agent');
    const inputAgentName = document.getElementById('agent-name-input');
    const agentsTableBody = document.getElementById('agents-table-body');
    const agentKeyBanner = document.getElementById('agent-key-banner');
    const newAgentKey = document.getElementById('new-agent-key');
    const btnCopyKey = document.getElementById('btn-copy-key');
    const btnCloseKeyBanner = document.getElementById('btn-close-key-banner');

    async function loadAgents() {
        try {
            const res = await fetch('/api/agents');
            const agents = await res.json();
            agentsTableBody.innerHTML = '';
            agents.forEach(a => {
                const tr = document.createElement('tr');
                
                const tdName = document.createElement('td');
                tdName.textContent = a.name;

                const tdKey = document.createElement('td');
                tdKey.className = 'api-key-text';
                tdKey.textContent = a.api_key;

                const tdDate = document.createElement('td');
                tdDate.textContent = new Date(a.created_at).toLocaleString();

                const tdActions = document.createElement('td');
                const btnDelete = document.createElement('button');
                btnDelete.className = 'btn danger';
                btnDelete.textContent = 'Delete';
                btnDelete.onclick = () => deleteAgent(a.id);
                tdActions.appendChild(btnDelete);

                tr.appendChild(tdName);
                tr.appendChild(tdKey);
                tr.appendChild(tdDate);
                tr.appendChild(tdActions);

                agentsTableBody.appendChild(tr);
            });
        } catch (e) {
            console.error("Failed to load agents", e);
        }
    }

    btnCreateAgent.addEventListener('click', async () => {
        const name = inputAgentName.value.trim();
        if(!name) return;
        try {
            const res = await fetch('/api/agents', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name})
            });
            if (res.ok) {
                const data = await res.json();
                inputAgentName.value = '';
                if (data.api_key) {
                    newAgentKey.textContent = data.api_key;
                    agentKeyBanner.style.display = 'block';
                    btnCopyKey.textContent = 'Copy';
                }
                loadAgents();
            }
        } catch (e) {
            console.error("Failed to create agent", e);
        }
    });

    if (btnCopyKey) {
        btnCopyKey.addEventListener('click', () => {
            if (newAgentKey.textContent) {
                navigator.clipboard.writeText(newAgentKey.textContent);
                btnCopyKey.textContent = 'Copied!';
                setTimeout(() => { btnCopyKey.textContent = 'Copy'; }, 2000);
            }
        });
    }

    if (btnCloseKeyBanner) {
        btnCloseKeyBanner.addEventListener('click', () => {
            agentKeyBanner.style.display = 'none';
        });
    }

    window.deleteAgent = async (id) => {
        await fetch(`/api/agents/${id}`, { method: 'DELETE' });
        loadAgents();
    };

    // Secrets API
    const btnCreateSecret = document.getElementById('btn-create-secret');
    const inputSecretKey = document.getElementById('secret-key-input');
    const inputSecretVal = document.getElementById('secret-val-input');
    const secretsTableBody = document.getElementById('secrets-table-body');

    async function loadSecrets() {
        try {
            const res = await fetch('/api/secrets');
            const secrets = await res.json();
            secretsTableBody.innerHTML = '';
            secrets.forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${s.key_name}</td>
                    <td>${new Date(s.created_at).toLocaleString()}</td>
                    <td><button class="btn danger" onclick="deleteSecret(${s.id})">Delete</button></td>
                `;
                secretsTableBody.appendChild(tr);
            });
        } catch(e) {
            console.error("Failed to load secrets", e);
        }
    }

    btnCreateSecret.addEventListener('click', async () => {
        const key_name = inputSecretKey.value.trim();
        const secret_value = inputSecretVal.value.trim();
        if(!key_name || !secret_value) return;
        await fetch('/api/secrets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({key_name, secret_value})
        });
        inputSecretKey.value = '';
        inputSecretVal.value = '';
        loadSecrets();
    });

    window.deleteSecret = async (id) => {
        await fetch(`/api/secrets/${id}`, { method: 'DELETE' });
        loadSecrets();
    };

    // Approvals API
    const approvalsTableBody = document.getElementById('approvals-table-body');
    let approvalsInterval = null;

    async function loadApprovals() {
        try {
            const res = await fetch('/api/approvals');
            const approvals = await res.json();
            approvalsTableBody.innerHTML = '';
            approvals.forEach(a => {
                const tr = document.createElement('tr');
                
                const tdReason = document.createElement('td');
                tdReason.textContent = a.reason;
                
                const tdSessionId = document.createElement('td');
                tdSessionId.textContent = a.session_id.substring(0, 8) + '...';
                
                const tdDate = document.createElement('td');
                tdDate.textContent = new Date(a.created_at).toLocaleString();

                const tdStatus = document.createElement('td');
                tdStatus.innerHTML = `<span style="font-weight: bold; color: ${a.status === 'pending' ? 'orange' : (a.status === 'approved' ? 'green' : 'red')}">${a.status}</span>`;

                const tdActions = document.createElement('td');
                if (a.status === 'pending') {
                    tdActions.innerHTML = `
                        <button class="btn primary" onclick="resolveApproval(${a.id}, 'approved')" style="margin-right: 8px;">Approve</button>
                        <button class="btn danger" onclick="resolveApproval(${a.id}, 'denied')">Deny</button>
                    `;
                }
                
                tr.appendChild(tdReason);
                tr.appendChild(tdSessionId);
                tr.appendChild(tdDate);
                tr.appendChild(tdStatus);
                tr.appendChild(tdActions);
                
                approvalsTableBody.appendChild(tr);
            });
        } catch(e) {
            console.error("Failed to load approvals", e);
        }
    }

    window.resolveApproval = async (id, status) => {
        await fetch(`/api/approvals/${id}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({status})
        });
        loadApprovals();
    };

    setInterval(() => {
        const approvalsView = document.getElementById('approvals-view');
        if (approvalsView && approvalsView.classList.contains('active')) {
            loadApprovals();
        }
    }, 2000);

    // Logs SSE Setup
    const logsOutput = document.getElementById('logs-output');
    if (logsOutput) {
        logsOutput.innerHTML = '';
        const eventSource = new EventSource('/api/logs/stream');
        eventSource.onmessage = function(event) {
            const data = event.data;
            if(!data) return;
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            logEntry.style.fontFamily = 'monospace';
            logEntry.style.padding = '4px 0';
            logEntry.style.borderBottom = '1px solid #333';
            try {
                const parsed = JSON.parse(data);
                logEntry.textContent = `[${parsed.timestamp || new Date().toISOString()}] ${parsed.type || 'EVENT'}: ${JSON.stringify(parsed.event || parsed)}`;
            } catch(e) {
                logEntry.textContent = data;
            }
            logsOutput.appendChild(logEntry);
            logsOutput.scrollTop = logsOutput.scrollHeight;
        };
    }
});
