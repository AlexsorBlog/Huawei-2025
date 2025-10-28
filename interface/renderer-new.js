// renderer.js
// Перекладено українською та додано логіку акордеону

// === 💡 Хелпери (safe, flatten) ===

function safe(v) {
    return v === null || v === undefined ? "" : v;
}

function flatten(obj, prefix = "", out = {}) {
    for (const [k, v] of Object.entries(obj || {})) {
        const newKey = prefix ? `${prefix}.${k}` : k;
        if (typeof v === "object" && !Array.isArray(v) && v !== null) {
            flatten(v, newKey, out);
        } else {
            const displayValue = (typeof v === 'string' && v.length > 200) ? v.substring(0, 197) + '...' : v;
            out[newKey] = safe(displayValue);
        }
    }
    return out;
}

// =================================================================
// === ФУНКЦІЇ РЕНДЕРИНГУ HTML ===
// =================================================================

/**
 * Створює HTML-таблицю Ключ-Значення з заголовком-акордеоном.
 * @param {string} title - Заголовок секції.
 * @param {Array<Array<string>>} rows - Масив пар [ключ, значення].
 * @param {boolean} isExpanded - Чи розгорнута секція за замовчуванням.
 */
function renderKeyValueTable(title, rows, isExpanded = false) {
    const collapsedClass = isExpanded ? '' : 'collapsed';
    
    let html = `<h2 class="collapsible-header ${collapsedClass}">${title}</h2>`;
    html += `<div class="collapsible-content ${collapsedClass}">`;
    html += `<div class="table-wrapper">`; // Обгортка для тіні і кутів
    html += '<table class="data-table"><tbody>';
    
    rows.forEach(([key, value]) => {
        const isCritical = (key.includes('Критичні тривоги') && parseInt(value) > 0) || (typeof value === 'string' && /down|fail/i.test(value));
        const valueClass = isCritical ? 'critical' : '';
        html += `<tr><th>${safe(key)}</th><td class="${valueClass}">${safe(value)}</td></tr>`;
    });
    
    html += '</tbody></table>';
    html += `</div></div>`; // Закриваємо .table-wrapper та .collapsible-content
    return html;
}

/**
 * Створює HTML-таблицю зі структурою (для списків) з заголовком-акордеоном.
 * @param {string} title - Заголовок секції.
 * @param {Array<string>} headers - Заголовки стовпців.
 * @param {Array<object>} data - Масив об'єктів з даними.
 * @param {string} keyForCritical - Ключ для визначення критичності рядка.
 * @param {boolean} isExpanded - Чи розгорнута секція за замовчуванням.
 */
function renderStructuredTable(title, headers, data, keyForCritical = null, isExpanded = false) {
    const collapsedClass = isExpanded ? '' : 'collapsed';

    if (!data || data.length === 0) {
        return `<h2 class="collapsible-header ${collapsedClass}">${title}</h2><div class="collapsible-content ${collapsedClass}"><div class="table-wrapper"><p class="text-gray-400 p-4">Немає даних.</p></div></div>`;
    }

    let html = `<h2 class="collapsible-header ${collapsedClass}">${title}</h2>`;
    html += `<div class="collapsible-content ${collapsedClass}">`;
    html += `<div class="table-wrapper">`; // Обгортка
    html += `<table class="data-table wide-cols"><thead><tr>`;
    headers.forEach(h => html += `<th>${h}</th>`);
    html += `</tr></thead><tbody>`;

    data.forEach(item => {
        const severityValue = item[keyForCritical] || '';
        const isCritical = keyForCritical && /critical|major|down|fail/i.test(severityValue);
        const rowClass = isCritical ? 'critical' : '';
        
        html += `<tr class="${rowClass}">`;
        
        headers.forEach(headerKey => {
            // Перетворюємо заголовок (напр. "Довжина хвилі (Нм)") в ключ (напр. "довжина_хвилі_(нм)")
            // Це може бути неідеально, краще мати мапінг, але спробуємо так
            const itemKey = headerKey.toLowerCase().replace(/ /g, '_').replace(/[\(\)]/g, ''); 
            
            // Спробуємо знайти ключ. Якщо ні, спробуємо оригінальний англійський ключ (якщо він є)
            let value = safe(item[itemKey]);
            
            // Якщо значення не знайдено за українським ключем, спробуємо поширені англійські
            if (value === "") {
                 const keyMap = {
                    "Ім'я": "name", "Статус": "status", "Протокол": "protocol", "Опис": "description",
                    "Рівень": "severity", "Стан": "state", "Дата": "date", "Час": "time",
                    "Слот": "slot", "Тип": "type", "Роль": "role",
                    "Порт": "port",
                    "Назва": "item_name", "Використано": "used_value", "Ліміт": "control_value"
                 };
                 if(keyMap[headerKey]) {
                    value = safe(item[keyMap[headerKey]]);
                 }
                 // Для ключів, яких немає в мапінгу
                 else if (itemKey === "in_util" || itemKey === "out_util" || itemKey === "дуплекс" || itemKey === "швидкість_(mbps)") {
                     const engKey = headerKey.toLowerCase().replace(' (mbps)', '_mbps').split(' ')[0];
                     value = safe(item[engKey]);
                 } else if (headerKey === "Довжина хвилі (Нм)") {
                    value = safe(item["wavelength_nm"]);
                 } else if(headerKey === "Онлайн") {
                    value = safe(item["online"]);
                 }
            }


            let cellClass = '';
            if (itemKey.includes('статус') || itemKey.includes('протокол') || headerKey === "Статус" || headerKey === "Протокол") {
                if (/up/i.test(value)) cellClass = 'up';
                if (/down|fail/i.test(value)) cellClass = 'down';
            }
            
            html += `<td class="${cellClass}">${value}</td>`;
        });
        
        html += `</tr>`;
    });

    html += '</tbody></table>';
    html += `</div></div>`; // Закриваємо .table-wrapper та .collapsible-content
    return html;
}

/**
 * Рендерить Головну сторінку (Summary, Identity, Resources і т.д.) в HTML.
 */
function makeMainHtml(d) {
    const deviceName = d.identity?.sysname || "Невідомий пристрій";
    let html = '';

    // 1. Summary (Зведення)
    const activeInterfaces = (d.interfaces || []).filter(i => /up/i.test(i.status) && i.name && !i.name.includes("LoopBack") && !i.name.includes("NULL")).length;
    const criticalAlarms = (d.alarms || []).filter(a => /critical/i.test(a.severity || a.level)).length;
    const totalPower = (d.resources?.power?.reduce((s, p) => s + (p.total_w || 0), 0) || 0) + " W";
    
    const summaryRows = [
        ["Ім'я хоста", d.identity?.sysname || deviceName],
        ["Модель", d.identity?.model || ""],
        ["Версія", d.software?.version || ""],
        ["Час роботи", d.software?.uptime || ""],
        ["CPU (сер.)", (d.resources?.cpu?.[0]?.avg || "") + "%"],
        ["Загальна потужність", totalPower],
        ["Критичні тривоги", criticalAlarms],
        ["Активні інтерфейси", activeInterfaces],
    ];
    // Розгортаємо першу секцію за замовчуванням
    html += renderKeyValueTable("Зведена інформація (Summary)", summaryRows, true); 
    
    // 2. Identity & Software
    const identityRows = Object.entries(d.identity || {}).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v, null, 2) : v]);
    html += renderKeyValueTable("Ідентифікація (Identity)", identityRows);
    
    const softwareRows = Object.entries(d.software || {}).map(([k, v]) => [k, v]);
    html += renderKeyValueTable("ПЗ (Software)", softwareRows);

    // 3. Resources (Ресурси)
    const resourceRows = [];
    Object.entries(d.resources || {}).forEach(([k, v]) => {
        if (typeof v === "object" && !Array.isArray(v)) {
            const flat = flatten(v);
            for (const [fk, fv] of Object.entries(flat)) resourceRows.push([`${k}.${fk}`, safe(fv)]);
        } else if (Array.isArray(v) && v.length > 0) {
            const flat = flatten(v[0]);
            for (const [fk, fv] of Object.entries(flat)) resourceRows.push([`${k}.[0].${fk}`, safe(fv)]);
        } else {
            resourceRows.push([k, safe(v)]);
        }
    });
    html += renderKeyValueTable("Ресурси (Resources)", resourceRows);

    // 4. Hardware (Плати і SFP)
    const cardHeaders = ["Слот", "Тип", "Онлайн", "Статус", "Роль"];
    html += renderStructuredTable("Плати (Hardware Cards)", cardHeaders, d.hardware?.cards, 'Status');

    const sfpHeaders = ["Порт", "Довжина хвилі (Нм)"];
    html += renderStructuredTable("SFP-модулі (Hardware SFP)", sfpHeaders, d.hardware?.sfp);

    // 5. Interfaces (Інтерфейси)
    const interfaceHeaders = ["Ім'я", "Статус", "Протокол", "In Util", "Out Util", "Дуплекс", "Швидкість (Mbps)", "Опис"];
    const interfaceData = (d.interfaces || []).filter(i => i.name);
    html += renderStructuredTable("Інтерфейси (Interfaces)", interfaceHeaders, interfaceData, 'Статус');

    // 6. Licenses (Ліцензії)
    const licenseHeaders = ["Назва", "Використано", "Ліміт", "Опис"];
    html += renderStructuredTable("Ліцензії (Licenses)", licenseHeaders, d.licenses);

    // 7. Alarms (Аварійні сигнали)
    const alarmHeaders = ["Рівень", "Стан", "Дата", "Час", "Опис"];
    const alarmData = (d.alarms || []).map(a => ({ 
        ...a, 
        severity: a.severity || a.level // Нормалізуємо ключ для сортування
    }));
    html += renderStructuredTable("Аварійні сигнали (Alarms)", alarmHeaders, alarmData, 'severity');

    return html;
}

/**
 * Рендерить Протоколи в HTML.
 */
function extractProtocolsHtml(d) {
    const protocolRows = [];
    
    for (const [proto, content] of Object.entries(d.protocols || {})) {
        if (!content) continue;

        if (Array.isArray(content)) {
            content.forEach((item, i) => {
                const flat = flatten(item);
                for (const [k, v] of Object.entries(flat)) {
                    protocolRows.push({ protocol: proto, field: `${i + 1}.${k}`, value: safe(v) });
                }
            });
        } else if (typeof content === "object") {
            for (const [subkey, subval] of Object.entries(content)) {
                if (Array.isArray(subval)) {
                    subval.forEach((el, j) => {
                        const flat = flatten(el);
                        for (const [k, v] of Object.entries(flat)) {
                            protocolRows.push({ protocol: proto, field: `${subkey}[${j + 1}].${k}`, value: safe(v) });
                        }
                    });
                } else if (typeof subval === "object") {
                    const flat = flatten(subval);
                    for (const [k, v] of Object.entries(flat)) {
                        protocolRows.push({ protocol: proto, field: `${subkey}.${k}`, value: safe(v) });
                    }
                } else {
                    protocolRows.push({ protocol: proto, field: subkey, value: safe(subval) });
                }
            }
        } else {
            protocolRows.push({ protocol: proto, field: "", value: safe(content) });
        }
    }

    const protocolHeaders = ["Протокол", "Поле", "Значення"];
    return renderStructuredTable("Деталі Протоколів (Protocols Detail)", protocolHeaders, protocolRows);
}


// =================================================================
// === ГОЛОВНЕ ВИКОНАННЯ ===
// =================================================================
// Переименовываем 'file' в 'jsonPath' для ясности
async function handleFileSelect(jsonPath, button = "view") { 
    if (!jsonPath) { 
        document.getElementById('json-output').innerHTML = '<p class="text-gray-400">Файл не обрано.</p>';
        return;
    }

    try {
        let data;
        if (button === "view") {
            // 1. Вызов IPC для чтения файла (это заменит весь FileReader)
            const ipcResponse = await window.electronAPI.readFile(jsonPath); 

            if (!ipcResponse || !ipcResponse.success) {
                const errorMessage = ipcResponse?.error || "Невідома помилка читання файлу.";
                throw new Error(errorMessage);
            }

            const jsonString = ipcResponse.content; 
            if (!jsonString) {
                throw new Error("Файл не містить даних.");
            }

            // 2. Парсинг строки JSON, полученной из Main Process
            data = JSON.parse(jsonString); 
            
            // 3. Отображение
            window.currentJsonPath = jsonPath; // Используем jsonPath
            const baseNameWithExt = jsonPath.split(/[/\\]/).pop(); 
            const baseName = baseNameWithExt.replace(/\.json$/i, '');
            const deviceName = data.identity?.sysname || baseName || 'Device';
            document.getElementById('device-title').textContent = `${deviceName} — Зведений Звіт`;

            let htmlOutput = makeMainHtml(data);
            htmlOutput += '<h1>Детальні Протоколи</h1>';
            htmlOutput += extractProtocolsHtml(data);
            document.getElementById('json-output').innerHTML = htmlOutput;
        } 
    } catch (error) {
        console.error('Помилка при обробці файлу:', error);

        const errorDiv = `...`;
        document.getElementById('json-output').innerHTML = errorDiv;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const jsonFileInput = document.getElementById('json-file-input');
    const logFileInput = document.getElementById('log-file-input');
    const xlsxFileInput = document.getElementById('xlsx-file-input');
    const outputDiv = document.getElementById('json-output');

    jsonFileInput.addEventListener('click', async () => {
                outputDiv.innerHTML = '<p class="text-lg text-gray-400">Очікуємо вибір json-файлу...</p>';

        try {
            const inputPath = await window.electronAPI.openFileDialog([
                { name: 'Json Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ]);

            if (!inputPath) {
                // Обработка отмены
                outputDiv.innerHTML = '<p class="text-gray-400">Вибір файлу скасовано.</p>';
                return;
            }
            outputDiv.innerHTML = '<p class="text-lg text-gray-400">Відкриття перегляду...</p>';
            
            // Ask main to parse the file (main will call analyzer.parseFile)
            await handleFileSelect(inputPath, "view");
            
        } catch (err) {
            console.error('Ошибка парсинга:', err);
            outputDiv.innerHTML = `<p class="text-lg text-red-500">❌ Помилка: ${err.message}</p>`;
        }
    });
    
    logFileInput.addEventListener('click', async () => {
        outputDiv.innerHTML = '<p class="text-lg text-gray-400">Очікуємо вибір лог-файлу...</p>';

        try {
            // ПРЯМОЙ ВЫЗОВ СИСТЕМНОГО ДИАЛОГА (Electron API)
            const inputPath = await window.electronAPI.openFileDialog([
                { name: 'Log Files', extensions: ['txt', 'log'] },
                { name: 'All Files', extensions: ['*'] }
            ]);

            if (!inputPath) {
                // Обработка отмены
                outputDiv.innerHTML = '<p class="text-gray-400">Вибір файлу скасовано.</p>';
                return;
            }
            outputDiv.innerHTML = '<p class="text-lg text-gray-400">Парсинг та обробка логу...</p>';
            
            // Ask main to parse the file (main will call analyzer.parseFile)
            const res = await window.electronAPI.analyzeStart('--file', inputPath);
            if (!res || !res.success) throw new Error(res?.error || 'Analyzer failed');
            
            // store the path to the generated JSON for later (export/view)
            window.currentJsonPath = res.outputPath;
            outputDiv.innerHTML = '✅ Аналіз лог-файлу завершено.';
            
        } catch (err) {
            console.error('Ошибка парсинга:', err);
            outputDiv.innerHTML = `<p class="text-lg text-red-500">❌ Помилка: ${err.message}</p>`;
        }
    });

    xlsxFileInput.addEventListener('click', async () => {
        outputDiv.innerHTML = '<p class="text-lg text-gray-400">Очікуємо вибір json-файлу...</p>';

        try {
            // ПРЯМОЙ ВЫЗОВ СИСТЕМНОГО ДИАЛОГА (Electron API)
            const inputPath = await window.electronAPI.openFileDialog([
                { name: 'Log Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ]);

            if (!inputPath) {
                // Обработка отмены
                outputDiv.innerHTML = '<p class="text-gray-400">Вибір файлу скасовано.</p>';
                return;
            }
            outputDiv.innerHTML = '<p class="text-lg text-gray-400">Експортування файлу...</p>';
            
            // Ask main to parse the file (main will call analyzer.parseFile)
            const res = await window.electronAPI.exportToExcel(inputPath);
            if (!res || !res.success) throw new Error(res?.error || 'Export failed');
            
            // store the path to the generated JSON for later (export/view)
            window.currentJsonPath = res.outputPath;
            outputDiv.innerHTML = '✅ Експортування завершено.';
            
        } catch (err) {
            console.error('Помилка експорту:', err);
            outputDiv.innerHTML = `<p class="text-lg text-red-500">❌ Помилка: ${err.message}</p>`;
        }
    });

    // --- ЛОГІКА АКОРДЕОНУ ---
    // Додаємо слухача на `json-output`, оскільки контент динамічний
    outputDiv.addEventListener('click', (event) => {
        // Перевіряємо, чи клікнули на заголовок h2
        const header = event.target.closest('h2.collapsible-header');
        if (!header) return;

        // Знаходимо наступний елемент (контент)
        const content = header.nextElementSibling;
        if (content && content.classList.contains('collapsible-content')) {
            // Перемикаємо класи
            header.classList.toggle('collapsed');
            content.classList.toggle('collapsed');
        }
    });
});

