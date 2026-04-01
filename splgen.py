from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Повна база шаблонів SPL для всіх 10 векторів з Excel-таблиці
SPL_TEMPLATES = {
    "malware": {
        "name": "1. Шкідливе ПЗ (EDR)",
        "desc": "Пошук статусів відпрацювання антивірусу по конкретному хосту або хешу.",
        "fields": [{"id": "hash", "label": "SHA256 Hash"}, {"id": "host", "label": "Hostname (напр. WS-001)"}],
        "base": 'index=edr_logs (SHA256="{hash}" OR ComputerName="*{host}*")'
    },
    "brute_force": {
        "name": "2. Брутфорс / Password Spraying",
        "desc": "Пошук подій автентифікації для вказаного IP.",
        "fields": [{"id": "ip", "label": "Source IP"}],
        "base": 'index=windows (EventCode=4625 OR EventCode=4624) src_ip="{ip}"'
    },
    "phishing": {
        "name": "3. Фішинг (Proxy Logs)",
        "desc": "Перевірка переходів за підозрілим посиланням.",
        "fields": [{"id": "domain", "label": "Domain / URL (без https://)"}],
        "base": 'index=proxy url="*{domain}*"'
    },
    "impossible_travel": {
        "name": "4. Аномальний доступ (Impossible Travel)",
        "desc": "Аналіз логів входу Azure AD / VPN для пошуку гео-аномалій.",
        "fields": [{"id": "user", "label": "UserName (напр. j.doe@bank.ua)"}],
        "base": 'index=azure_ad Category=SignInLogs user="{user}"'
    },
    "lotl": {
        "name": "5. Підозрілий процес (LotL)",
        "desc": "Пошук аномальних батьківських процесів, що запускають командні оболонки.",
        "fields": [{"id": "parent", "label": "Parent Process (напр. winword.exe)"}, {"id": "child", "label": "Child Process (напр. powershell.exe)"}],
        "base": 'index=sysmon EventCode=1 ParentImage="*{parent}*" Image="*{child}*"'
    },
    "data_exfil": {
        "name": "6. Витік даних (Data Exfiltration)",
        "desc": "Пошук вихідного трафіку на зовнішні ресурси для конкретного IP.",
        "fields": [{"id": "src_ip", "label": "Внутрішній IP користувача"}],
        "base": 'index=firewall src_ip="{src_ip}" action=allowed'
    },
    "mfa_fatigue": {
        "name": "7. MFA Fatigue (MFA Bombing)",
        "desc": "Аналіз відхилених та успішних запитів MFA по конкретному юзеру.",
        "fields": [{"id": "user", "label": "UserName"}],
        "base": 'index=azure_ad OperationName="Sign-in activity" user="{user}"'
    },
    "ransomware": {
        "name": "8. Ознаки Ransomware",
        "desc": "Пошук масових файлових операцій (Modify/Delete) на хості.",
        "fields": [{"id": "host", "label": "Hostname (напр. FS-01)"}],
        "base": 'index=windows EventCode=4663 ComputerName="*{host}*"'
    },
    "inbox_rule": {
        "name": "9. Підозрілі правила пошти (Inbox Forwarding)",
        "desc": "Пошук створення правил пересилання (Forwarding) поштової скриньки.",
        "fields": [{"id": "user", "label": "Mailbox Owner (UserName)"}],
        "base": 'index=m365 Workload=Exchange (Operation=New-InboxRule OR Operation=Set-InboxRule) UserId="{user}"'
    },
    "cleartext_pass": {
        "name": "10. Паролі у відкритому вигляді",
        "desc": "Пошук використання ключів передачі паролів у командному рядку.",
        "fields": [{"id": "keyword", "label": "Ключове слово (напр. password, -p, pwd=)"}],
        "base": 'index=sysmon EventCode=1 CommandLine="*{keyword}*"'
    }
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="uk" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>SOC L1 - Advanced SPL Generator</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #121212; color: #e0e0e0; font-family: 'Consolas', monospace; }
        .card { background-color: #1e1e1e; border: 1px solid #333; }
        pre { background-color: #000; padding: 15px; border-radius: 5px; color: #4af626; border: 1px solid #333; white-space: pre-wrap;}
        .btn-custom { background-color: #e20074; color: white; border: none; }
        .btn-custom:hover { background-color: #b0005a; color: white; }
        .form-switch .form-check-input:checked { background-color: #e20074; border-color: #e20074; }
    </style>
</head>
<body>
<div class="container mt-4 mb-5">
    <h2 class="mb-4 text-center">Cyber Academy: Advanced SPL Generator</h2>
    
    <div class="row">
        <div class="col-md-5">
            <div class="card p-4 mb-3">
                <h5 class="text-warning">1. Основний пошук (Base Search)</h5>
                <select id="vectorSelect" class="form-select mb-3 border-secondary" onchange="loadFields()">
                    <option value="" selected disabled>-- Оберіть тип алерту --</option>
                    {% for key, data in templates.items() %}
                        <option value="{{ key }}">{{ data.name }}</option>
                    {% endfor %}
                </select>
                <p id="descText" class="text-muted small"></p>

                <div id="dynamicFields">
                    </div>
            </div>

            <div class="card p-4">
                <h5 class="text-info">2. Модифікатори (Pipeline Options)</h5>
                
                <label class="form-label mt-2 text-muted small">Формат виводу (Опціонально):</label>
                <select id="outputFormat" class="form-select border-secondary mb-3 bg-dark text-light">
                    <option value="raw" selected>Сирі логи (Raw Events)</option>
                    <option value="table">Таблиця (| table _time, src_ip, user...)</option>
                    <option value="stats_ip">Статистика по IP (| stats count by src_ip)</option>
                    <option value="stats_user">Статистика по Юзерам (| stats count by user)</option>
                </select>

                <label class="form-label text-muted small">Швидкі фільтри:</label>
                <div class="form-check form-switch mb-1">
                    <input class="form-check-input" type="checkbox" id="modDedup">
                    <label class="form-check-label small" for="modDedup">| dedup (Прибрати дублікати)</label>
                </div>
                <div class="form-check form-switch mb-1">
                    <input class="form-check-input" type="checkbox" id="modSort" checked>
                    <label class="form-check-label small" for="modSort">| sort - _time (Нові зверху)</label>
                </div>

                <label class="form-label mt-3 text-muted small">Кастомний фільтр (напр. | where count > 10):</label>
                <input type="text" class="form-control bg-dark text-light border-secondary" id="customFilter" placeholder="| search action=blocked">

                <button class="btn btn-custom w-100 mt-4 fw-bold" onclick="generateSPL()">🚀 Згенерувати SPL</button>
            </div>
        </div>

        <div class="col-md-7">
            <div class="card p-4 h-100 sticky-top" style="top: 20px;">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h4 class="m-0 text-success">Готовий SPL Запит</h4>
                    <button class="btn btn-outline-light btn-sm" onclick="copySPL()">📋 Копіювати</button>
                </div>
                <pre id="splOutput">Оберіть вектор та налаштуйте фільтри для генерації...</pre>
            </div>
        </div>
    </div>
</div>

<script>
    const templatesData = {{ templates|tojson }};
    
    function loadFields() {
        const selected = document.getElementById('vectorSelect').value;
        const container = document.getElementById('dynamicFields');
        const descText = document.getElementById('descText');
        container.innerHTML = '';
        
        if(selected && templatesData[selected]) {
            descText.innerText = templatesData[selected].desc;
            templatesData[selected].fields.forEach(field => {
                container.innerHTML += `
                    <div class="mb-2">
                        <label class="form-label small text-info">${field.label}</label>
                        <input type="text" class="form-control bg-dark text-light border-secondary dynamic-input" id="${field.id}" placeholder="*">
                    </div>
                `;
            });
        }
    }

    async function generateSPL() {
        const selected = document.getElementById('vectorSelect').value;
        if (!selected) {
            alert("Оберіть вектор атаки!"); return;
        }

        let payload = { 
            vector: selected, 
            params: {},
            modifiers: {
                format: document.getElementById('outputFormat').value,
                dedup: document.getElementById('modDedup').checked,
                sort: document.getElementById('modSort').checked,
                custom: document.getElementById('customFilter').value.trim()
            }
        };

        // Збір значень з полів вводу. Якщо пусте - ставимо *
        document.querySelectorAll('.dynamic-input').forEach(input => {
            payload.params[input.id] = input.value.trim() || "*";
        });

        const response = await fetch('/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        document.getElementById('splOutput').innerText = data.spl;
    }

    function copySPL() {
        const text = document.getElementById('splOutput').innerText;
        navigator.clipboard.writeText(text);
        const btn = document.querySelector('.btn-outline-light');
        btn.innerText = "✅ Скопійовано!";
        setTimeout(() => btn.innerText = "📋 Копіювати", 2000);
    }
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, templates=SPL_TEMPLATES)

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    vector = data.get('vector')
    params = data.get('params', {})
    modifiers = data.get('modifiers', {})
    
    if vector not in SPL_TEMPLATES:
        return jsonify({'spl': 'Помилка: Вектор не знайдено'})

    base_query = SPL_TEMPLATES[vector]['base'].format(**params)
    spl_lines = [base_query]

    if modifiers.get('custom'):
        custom_pipe = modifiers['custom']
        if not custom_pipe.startswith('|'):
            custom_pipe = '| ' + custom_pipe
        spl_lines.append(custom_pipe)

    fmt = modifiers.get('format')
    if fmt == 'table':
        spl_lines.append('| table _time, ComputerName, src_ip, dest_ip, user, EventCode, action, url, CommandLine')
    elif fmt == 'stats_ip':
        if vector == 'brute_force':
            spl_lines.append('| stats count as attempts, dc(TargetUserName) as unique_users, values(TargetUserName) as users by src_ip, EventCode')
        else:
            spl_lines.append('| stats count by src_ip, action')
    elif fmt == 'stats_user':
        spl_lines.append('| stats count by user, src_ip')

    if modifiers.get('dedup'):
        if fmt == 'raw':
            spl_lines.append('| dedup _raw')
        elif fmt == 'table':
            spl_lines.append('| dedup _time, src_ip, user')
            
    if modifiers.get('sort'):
        if fmt.startswith('stats'):
            spl_lines.append('| sort - count')
        else:
            spl_lines.append('| sort - _time')

    final_spl = ' \n'.join(spl_lines)
    
    return jsonify({'spl': final_spl})

if __name__ == '__main__':
    print("🚀 SOC L1 Advanced Generator запущено! Відкрий http://127.0.0.1:5000 у браузері.")
    app.run(debug=True)