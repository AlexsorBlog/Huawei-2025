// renderer.js (v14)
// - Added filtering to only show files with a `deviceName` in the sidebar.
// - Sidebar now displays the `deviceName` instead of the `fileName`.
// - "Parse JSON" button now reads the file to get the `deviceName`.

// === 💡 Хелпери (safe, flatten) ===

function safe(v) {
    return v === null || v === undefined ? "" : v;
}

/**
 * Flattens a nested object.
 * - v10: Safely handles arrays by showing a count instead of [object Object].
 */
function flatten(obj, prefix = "", out = {}) {
    if (obj === null || obj === undefined) {
        return out;
    }
    
    for (const [k, v] of Object.entries(obj)) {
        const newKey = prefix ? `${prefix}.${k}` : k;
        
        if (Array.isArray(v)) {
            // Handle arrays: show a count instead of flattening
            out[newKey] = `[${v.length} items]`;
        } else if (typeof v === "object" && v !== null) {
            // Recurse into objects
            flatten(v, newKey, out);
        } else {
            // Handle primitive values
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
 * Creates an HTML Key-Value table with an accordion header.
 * @param {string} title - Section title.
 * @param {Array<Array<string>>} rows - Array of [key, value] pairs.
 * @param {boolean} isExpanded - Default expanded state.
 */
function renderKeyValueTable(title, rows, isExpanded = false) {
    const collapsedClass = isExpanded ? '' : 'collapsed';
    
    let html = `<h2 class="collapsible-header ${collapsedClass}">${title} (${rows.length})</h2>`;
    html += `<div class="collapsible-content ${collapsedClass}">`;
    html += `<div class="table-wrapper">`;
    html += '<table class="data-table"><tbody>';
    
    rows.forEach(([key, value]) => {
        const isCritical = (key.includes('Критичні тривоги') && parseInt(value) > 0) || (typeof value === 'string' && /down|fail/i.test(value));
        const valueClass = isCritical ? 'critical' : '';
        html += `<tr><th>${safe(key)}</th><td class="${valueClass}">${safe(value)}</td></tr>`;
    });
    
    html += '</tbody></table>';
    html += `</div></div>`;
    return html;
}

/**
 * Creates an HTML structured table (for lists) with an accordion header.
 * @param {string} title - Section title.
 * @param {Array<string>} headers - Column headers.
 * @param {Array<object>} data - Array of data objects.
 * @param {string} keyForCritical - Key to check for critical state.
 * @param {boolean} isExpanded - Default expanded state.
 */
function renderStructuredTable(title, headers, data, keyForCritical = null, isExpanded = false) {
    const collapsedClass = isExpanded ? '' : 'collapsed';
    const count = data ? data.length : 0;

    if (count === 0) {
        return `<h2 class="collapsible-header ${collapsedClass}">${title} (0)</h2><div class="collapsible-content ${collapsedClass}"><div class="table-wrapper"><p class="text-gray-400 p-4">Empty data.</p></div></div>`;
    }

    let html = `<h2 class="collapsible-header ${collapsedClass}">${title} (${count})</h2>`;
    html += `<div class="collapsible-content ${collapsedClass}">`;
    html += `<div class="table-wrapper">`;
    html += `<table class="data-table wide-cols"><thead><tr>`;
    headers.forEach(h => html += `<th>${h}</th>`);
    html += `</tr></thead><tbody>`;

    data.forEach(item => {
        const severityValue = item[keyForCritical] || '';
        const isCritical = keyForCritical && /critical|major|down|fail/i.test(String(severityValue));
        const rowClass = isCritical ? 'critical' : '';
        
        html += `<tr class="${rowClass}">`;
        
        headers.forEach(headerKey => {
            // Find the item key. We'll check for a few common formats.
            let itemKey = headerKey.toLowerCase().replace(/ /g, '_').replace(/[\(\)]/g, '');
            let value = item[itemKey];

            // If not found, try finding by original headerKey (if properties match)
            if (value === undefined && item[headerKey] !== undefined) {
                value = item[headerKey];
            }
            
            // If still not found, try some common mappings
            if (value === undefined) {
                 const keyMap = {
                    "Ім'я": "name", "Статус": "status", "Протокол": "protocol", "Опис": "description",
                    "Рівень": "severity", "Стан": "state", "Дата": "date", "Час": "time",
                    "Слот": "slot", "Тип": "type", "Роль": "role",
                    "Порт": "port", "Wavelength(nm)":"wavelength_nm", "Rx(dBm)": "rx_dbm", "Tx(dBm)": "tx_dbm",
                    "Назва": "item_name", "Використано": "used_value", "Ліміт": "control_value",
                    "Peer IP": "peer_ip", "Peer AS": "peer_as", "Local AS": "local_as", "BFD": "bfd",
                    "Interface": "interface", "Neighbor ID": "neighbor_id", "State": "state"
                 };
                 if(keyMap[headerKey]) {
                    value = item[keyMap[headerKey]];
                 }
            }
            
            value = safe(value); // Ensure it's not null/undefined

            let cellClass = '';
            if (itemKey.includes('status') || itemKey.includes('protocol') || itemKey.includes('state') || headerKey === "Статус" || headerKey === "Протокол" || headerKey === "State") {
                if (/up|master|normal|present|full/i.test(value)) cellClass = 'up';
                if (/down|fail|slave|abnormal/i.test(value)) cellClass = 'down';
            }
            
            html += `<td class="${cellClass}">${value}</td>`;
        });
        
        html += `</tr>`;
    });

    html += '</tbody></table>';
    html += `</div></div>`;
    return html;
}

/**
 * Renders Protocol Details into a grid of cards.
 * @param {string} title - Section title.
 * @param {Array<object>} data - Array of {protocol, field, value} objects.
 */
function renderProtocolDetails(title, data) {
    const count = data ? data.length : 0;
    const collapsedClass = 'collapsed'; // Always collapsed by default
    
    if (count === 0) {
        return `<h2 class="collapsible-header ${collapsedClass}">${title} (0)</h2><div class="collapsible-content ${collapsedClass}"><div class="protocol-grid"><p class="text-gray-400 p-4">Empty data.</p></div></div>`;
    }

    // Group data by protocol
    const grouped = data.reduce((acc, row) => {
        const key = row.Protocol; // Use the correct capitalized key
        if (!acc[key]) {
            acc[key] = [];
        }
        acc[key].push(row);
        return acc;
    }, {});

    let html = `<h2 class="collapsible-header ${collapsedClass}">${title} (${count})</h2>`;
    html += `<div class="collapsible-content ${collapsedClass}">`;
    html += `<div class="protocol-grid">`;

    // Create a card for each protocol
    for (const [protocolName, rows] of Object.entries(grouped)) {
        html += `
            <div class="protocol-card">
                <div class="protocol-card-header">${protocolName} (${rows.length})</div>
                <div class="protocol-card-content">
                    <table class="data-table minimal"><tbody>
        `;
        
        rows.forEach(row => {
            const value = safe(row.Value); // Use the correct capitalized key
            let valueClass = '';
            if (/up|master|normal/i.test(value)) valueClass = 'up';
            if (/down|fail|slave/i.test(value)) valueClass = 'down';
            
            html += `<tr>
                <th>${safe(row.Field)}</th>
                <td class="${valueClass}">${value}</td>
            </tr>`;
        });

        html += `
                    </tbody></table>
                </div>
            </div>
        `;
    }

    html += `</div></div>`; // Close .protocol-grid and .collapsible-content
    return html;
}


/**
 * Renders the Main page (Summary, Identity, Resources, etc.) in HTML.
 * @param {object} d - The full data object.
 */
function makeMainHtml(d) {
    const deviceName = d.identity?.sysname || "Unknown Device";
    let html = '';

    // 1. Summary (Зведення)
    const activeInterfaces = (d.interfaces || []).filter(i => /up/i.test(i.status) && i.name && !i.name.includes("LoopBack") && !i.name.includes("NULL")).length;
    const criticalAlarms = (d.alarms || []).filter(a => /critical|major/i.test(a.severity || a.level)).length;
    const totalPower = (d.resources?.power?.reduce((s, p) => s + (p.total_power_w || 0), 0) || 0) + " W";
    const sshUsers = (d.identity?.ssh_users || []).map(u => u.name).join(', ');
    
    const summaryRows = [
        ["Device name", d.identity?.sysname || deviceName],
        ["Model", d.identity?.model || ""],
        ["Version", d.software?.version || ""],
        ["Uptime", d.software?.uptime || ""],
        ["Router ID", d.identity?.router_id_public || ""],
        ["LSR ID", d.identity?.lsr_id || ""],
        ["Serial (ESN)", d.identity?.serial || ""],
        ["Timezone", d.identity?.timezone || ""],
        ["Current Time", d.identity?.current_time || ""],
        ["SSH Users", sshUsers],
        ["CPU (avg)", (d.resources?.cpu?.[0]?.avg || "") + "%"],
        ["Total Power", totalPower],
        ["Critical Alarms", criticalAlarms],
        ["Active Interfaces", activeInterfaces],
    ];
    html += renderKeyValueTable("Summary", summaryRows, true); // Expanded by default
    
    // 2. Resources (Ресурси)
    const resourceRows = [];
    Object.entries(d.resources || {}).forEach(([k, v]) => {
        if (typeof v === "object" && !Array.isArray(v) && v !== null) {
            const flat = flatten(v);
            for (const [fk, fv] of Object.entries(flat)) resourceRows.push([`${k}.${fk}`, safe(fv)]);
        } else if (Array.isArray(v) && v.length > 0) {
            // Flatten first item in array if it's an object
            if (typeof v[0] === 'object' && v[0] !== null) {
                const flat = flatten(v[0]);
                for (const [fk, fv] of Object.entries(flat)) resourceRows.push([`${k}.[0].${fk}`, safe(fv)]);
            } else {
                 resourceRows.push([k, `[${v.length} items]`]);
            }
        } else {
            resourceRows.push([k, safe(v)]);
        }
    });
    html += renderKeyValueTable("Resources", resourceRows);

    // 3. Hardware (Плати і SFP)
    const cardHeaders = ["Slot","Type","Online","Status","Role"];
    html += renderStructuredTable("Hardware Cards", cardHeaders, d.hardware?.cards, 'Status');
    
    const picHeaders = ["PIC", "Status", "Type", "Port Count", "Init Result", "Logic Down"];
    html += renderStructuredTable("Hardware PICs", picHeaders, d.hardware?.pics, 'Status');

    const sfpHeaders = ["port", "status", "vendor_pn", "Wavelength(nm)", "rx_dbm", "tx_dbm"];
    html += renderStructuredTable("Hardware SFP", sfpHeaders, d.hardware?.sfp, 'status');

    // 4. Interfaces (Інтерфейси)
    const interfaceHeaders = ["name", "status", "protocol", "ip", "mask", "vpn_instance", "bandwidth_mbps", "duplex", "description"];
    const interfaceData = (d.interfaces || []).filter(i => i.name);
    html += renderStructuredTable("Interfaces", interfaceHeaders, interfaceData, 'status');

    // 5. Routing & Protocols
    const vrfHeaders = ["Name", "Router ID", "Address Family"];
    html += renderStructuredTable("VPN Instances (VRF)", vrfHeaders, d.protocols?.vrfs, null);

    const isisHeaders = ["ID", "Network Entity", "IS Level"];
    html += renderStructuredTable("ISIS Processes", isisHeaders, d.protocols?.isis?.processes, null);

    const ospfHeaders = ["Area","Interface","Neighbor ID","State"];
    html += renderStructuredTable("OSPF Neighbors", ospfHeaders, d.protocols?.ospf?.neighbors, 'State');

    const bgpConfigHeaders = ["Peer IP", "Local AS", "Peer AS", "Description", "BFD"];
    html += renderStructuredTable("BGP Configured Peers", bgpConfigHeaders, d.protocols?.bgp?.config_peers, null);
    
    const bgpEvpnHeaders = ["Neighbor", "AS", "State", "Uptime", "Routes"];
    html += renderStructuredTable("BGP EVPN Peers", bgpEvpnHeaders, d.protocols?.bgp?.evpn_peers, 'State');

    // 6. Trunks & Tunnels
    const ethTrunkHeaders = ["ID", "Type", "State", "Mode", "Actor", "Partner"];
    html += renderStructuredTable("Eth-Trunks", ethTrunkHeaders, d.protocols?.trunks?.eth_trunks, 'State');

    const eTrunkHeaders = ["ID", "State", "Peer IP", "System ID"];
    html += renderStructuredTable("E-Trunks", eTrunkHeaders, d.protocols?.trunks?.e_trunks, 'State');
    
    const evpnHeaders = ["VPN-Instance", "EVI", "VNI"];
    html += renderStructuredTable("EVPN Instances", evpnHeaders, d.protocols?.evpn?.instances, null);

    const vxlanHeaders = ["VNI", "BD ID", "Peer IP", "Interface", "State"];
    html += renderStructuredTable("VXLAN VNIs", vxlanHeaders, d.protocols?.vxlan?.vnis, 'State');

    // 7. Licenses (Ліцензії)
    const licenseHeaders = ["item_name", "used_value", "control_value", "description"];
    html += renderStructuredTable("Licenses", licenseHeaders, d.licenses);

    // 8. Alarms (Аварійні сигнали)
    const alarmHeaders = ["severity", "state", "date", "time", "description"];
    const alarmData = (d.alarms || []).map(a => ({ 
        ...a, 
        severity: a.severity || a.level // Normalize key for sorting/color
    }));
    html += renderStructuredTable("Alarms", alarmHeaders, alarmData, 'severity');

    return html;
}


/**
 * Renders All Protocol data (from raw parsing) into HTML.
 * v11: Renders as a grid of cards.
 */
function extractProtocolsHtml(d) {
    const protocolRows = [];
    
    for (const [proto, content] of Object.entries(d.protocols || {})) {
        if (!content) continue;

        // Simplified flattening logic for the protocol grid
        const flattenProtocol = (data, prefix = "") => {
             if (Array.isArray(data)) {
                if (data.length === 0) {
                     protocolRows.push({ Protocol: proto, Field: prefix || "data", Value: "[empty array]" });
                     return;
                }
                // If array contains simple items or we just want to show a count
                if (typeof data[0] !== 'object') {
                     protocolRows.push({ Protocol: proto, Field: prefix, Value: data.join(', ') });
                } else {
                    // Handle arrays of objects by iterating
                    data.forEach((item, i) => {
                        flattenProtocol(item, `${prefix}[${i}]`);
                    });
                }
             } else if (typeof content === "object" && content !== null) {
                 for (const [key, value] of Object.entries(data)) {
                     const newKey = prefix ? `${prefix}.${key}` : key;
                     if (typeof value === "object" && value !== null && !Array.isArray(value)) {
                         flattenProtocol(value, newKey); // Recurse
                     } else if (Array.isArray(value)) {
                         protocolRows.push({ Protocol: proto, Field: newKey, Value: `[${value.length} items]`});
                     } else {
                         protocolRows.push({ Protocol: proto, Field: newKey, Value: safe(value) });
                     }
                 }
             } else {
                 protocolRows.push({ Protocol: proto, Field: prefix || "value", Value: safe(data) });
             }
        };
        
        // Start flattening for each main protocol
        flattenProtocol(content, proto);
    }

    return renderProtocolDetails("Protocols Detail", protocolRows);
}


// =================================================================
// === ГОЛОВНЕ ВИКОНАННЯ ===
// =================================================================

// Global cache for file content
const loadedFilesCache = new Map();
let currentActiveFile = null;

async function handleFileSelect(jsonPath) {
    if (!jsonPath) {
        document.getElementById('json-output').innerHTML = '<p class="text-gray-400">File not selected.</p>';
        return;
    }

    const outputDiv = document.getElementById('json-output');
    outputDiv.innerHTML = '<p class="text-lg text-gray-400">Opening view...</p>';
    
    try {
        let data;
        // Check cache first
        if (loadedFilesCache.has(jsonPath)) {
            data = loadedFilesCache.get(jsonPath);
        } else {
            // 1. Call IPC to read the file
            const ipcResponse = await window.electronAPI.readFile(jsonPath);

            if (!ipcResponse || !ipcResponse.success) {
                const errorMessage = ipcResponse?.error || "Unknown file reading error.";
                throw new Error(errorMessage);
            }

            const jsonString = ipcResponse.content;
            if (!jsonString) {
                throw new Error("File is empty or could not be read.");
            }

            // 2. Parse the JSON string
            data = JSON.parse(jsonString);
            loadedFilesCache.set(jsonPath, data); // Store in cache
        }
        
        // 3. Render
        currentActiveFile = jsonPath;
        updateFilelistActiveState();
        
        const baseNameWithExt = jsonPath.split(/[/\\]/).pop();
        const baseName = baseNameWithExt.replace(/\.json$/i, '');
        const deviceName = data.identity?.sysname || data.identity?.hostname || baseName || 'Device';
        document.getElementById('device-title').textContent = `${deviceName} — Summary View`;

        let htmlOutput = makeMainHtml(data);
        htmlOutput += extractProtocolsHtml(data);
        outputDiv.innerHTML = htmlOutput;
        
    } catch (error) {
        console.error('Error processing file:', error);
        outputDiv.innerHTML = `<div class="bg-[#2f3136] p-6 rounded-lg shadow-lg">
            <h2 class="text-2xl font-bold text-red-400 mb-4">❌ Error Processing File</h2>
            <p class="text-lg text-gray-300 mb-2">Could not read or parse: ${jsonPath.split(/[/\\]/).pop()}</p>
            <pre class="bg-[#202225] p-4 rounded-md text-red-300 overflow-auto text-sm">${error.stack}</pre>
        </div>`;
    }
}

/**
 * Populates the sidebar with a list of file paths.
 * @param {Array<object>} filesToShow - Array of { outputPath, deviceName } objects.
 */
function populateFileList(filesToShow) {
    const fileListDiv = document.getElementById('file-list');
    const fileListContainer = document.getElementById('file-list-container');
    if (!fileListDiv || !fileListContainer) return;

    // Clear cache and existing list
    loadedFilesCache.clear();
    fileListDiv.innerHTML = '';
    
    if (!filesToShow || filesToShow.length === 0) {
        fileListContainer.style.display = 'none'; // Hide if no files
        return;
    }
    
    fileListContainer.style.display = 'flex'; // Show the container

    filesToShow.forEach(file => {
        if (!file || !file.outputPath) return; // Safeguard against bad data
        
        const filePath = file.outputPath;
        const displayName = file.deviceName; // This is the new display name
        const fileName = filePath.split(/[/\\]/).pop(); // Keep filename for tooltip

        const itemDiv = document.createElement('div');
        itemDiv.className = 'file-item';
        itemDiv.dataset.filePath = filePath; // Store full path in data attribute
        
        // New HTML structure with export button
        itemDiv.innerHTML = `
            <div class="file-item-main" title="${displayName} (${fileName})">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0011.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg>
                <span>${displayName}</span>
            </div>
            <button class="file-export-btn" data-export-path="${filePath}" title="Export ${displayName} to Excel">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
            </button>
        `;
        
        fileListDiv.appendChild(itemDiv);
    });

    // Auto-select the first file if one exists
    const firstItem = fileListDiv.querySelector('.file-item');
    if (firstItem) {
        handleFileSelect(firstItem.dataset.filePath);
    }
}

/**
 * Updates the 'active' class on the file list based on currentActiveFile.
 */
function updateFilelistActiveState() {
    const fileListDiv = document.getElementById('file-list');
    if (!fileListDiv) return;
    
    const items = fileListDiv.querySelectorAll('.file-item');
    items.forEach(item => {
        if (item.dataset.filePath === currentActiveFile) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

// === DOMContentLoaded ===
document.addEventListener('DOMContentLoaded', () => {
    let currentMode = 'file';
    const modeFileBtn = document.getElementById('mode-file');
    const modeFolderBtn = document.getElementById('mode-folder');

    const jsonFileInput = document.getElementById('json-file-input');
    const logFileInput = document.getElementById('log-file-input');
    const xlsxFileInput = document.getElementById('xlsx-file-input');
    const outputDiv = document.getElementById('json-output');
    const fileListDiv = document.getElementById('file-list');

    function updateMode(newMode) {
        currentMode = newMode;

        // Управление стилями
        if (newMode === 'file') {
            modeFileBtn.classList.add('bg-[#5865F2]', 'text-white', 'shadow-md');
            modeFileBtn.classList.remove('text-gray-400', 'hover:bg-[#2f3136]');

            modeFolderBtn.classList.remove('bg-[#5865F2]', 'text-white', 'shadow-md');
            modeFolderBtn.classList.add('text-gray-400', 'hover:bg-[#2f3136]');
        } else { // 'directory'
            modeFolderBtn.classList.add('bg-[#5865F2]', 'text-white', 'shadow-md');
            modeFolderBtn.classList.remove('text-gray-400', 'hover:bg-[#2f3136]');

            modeFileBtn.classList.remove('bg-[#5865F2]', 'text-white', 'shadow-md');
            modeFileBtn.classList.add('text-gray-400', 'hover:bg-[#2f3136]');
        }
    }
    
    modeFileBtn.addEventListener('click', () => updateMode('file'));
    modeFolderBtn.addEventListener('click', () => updateMode('directory'));

    // Handle clicks on the file list (event delegation)
    if (fileListDiv) {
        fileListDiv.addEventListener('click', async (e) => {
            const fileItem = e.target.closest('.file-item');
            const exportBtn = e.target.closest('.file-export-btn');

            if (exportBtn) {
                // --- Handle Export Button Click ---
                e.stopPropagation(); // Stop click from bubbling to file-item
                const filePath = exportBtn.dataset.exportPath;
                if (!filePath) return;

                console.log(`Exporting single file: ${filePath}`);
                // Show temporary feedback in the main title
                const originalTitle = document.getElementById('device-title').textContent;
                document.getElementById('device-title').textContent = `Exporting ${filePath.split(/[/\\]/).pop()}...`;
                
                try {
                    const res = await window.electronAPI.exportToExcel(filePath, 'file');
                    if (!res || !res.success) throw new Error(res?.error || 'Export failed');
                    
                    // Show success
                    document.getElementById('device-title').textContent = `✅ Exported!`;
                    
                } catch (err) {
                    console.error('Error exporting file:', err);
                    document.getElementById('device-title').textContent = `❌ Export Failed`;
                }
                
                // Reset title after a delay
                setTimeout(() => {
                    // Only reset if it's still showing the export message
                    if (document.getElementById('device-title').textContent.startsWith('✅') || document.getElementById('device-title').textContent.startsWith('❌')) {
                         document.getElementById('device-title').textContent = originalTitle;
                    }
                }, 3000);

            } else if (fileItem && fileItem.dataset.filePath) {
                // --- Handle View File Click ---
                const filePath = fileItem.dataset.filePath;
                if (filePath !== currentActiveFile) {
                    handleFileSelect(filePath);
                }
            }
        });
    }

    // PARSE JSON button
    jsonFileInput.addEventListener('click', async () => {
        outputDiv.innerHTML = '<p class="text-lg text-gray-400">Choosing json file...</p>';
        try {
            const inputPath = await window.electronAPI.openFileDialog('view_input_path',[
                { name: 'Json Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ], 'file'); // Always 'file' mode for this button

            if (!inputPath) {
                outputDiv.innerHTML = '<p class="text-gray-400">Choose cancelled.</p>';
                return;
            }
            
            // v14: Read the file to get its device name
            outputDiv.innerHTML = '<p class="text-lg text-gray-400">Reading file...</p>';
            const ipcResponse = await window.electronAPI.readFile(inputPath);
            if (!ipcResponse || !ipcResponse.success) {
                throw new Error(ipcResponse?.error || "Could not read selected JSON file.");
            }
            const data = JSON.parse(ipcResponse.content);
            const deviceName = data.identity?.sysname || data.identity?.hostname || inputPath.split(/[/\\]/).pop();

            // Populate the file list with this single file object
            populateFileList([{ outputPath: inputPath, deviceName: deviceName }]);
            // handleFileSelect is called by populateFileList
            
        } catch (err) {
            console.error('Error viewing file:', err);
            outputDiv.innerHTML = `<p class="text-lg text-red-500">❌ Error: ${err.message}</p>`;
        }
    });

    // PARSE TXT/LOG button
    logFileInput.addEventListener('click', async () => {
        outputDiv.innerHTML = '<p class="text-lg text-gray-400">Choosing log file(s)...</p>';
        try {
            const inputPath = await window.electronAPI.openFileDialog('analyze_input_path',[
                { name: 'Log Files', extensions: ['txt', 'log'] },
                { name: 'All Files', extensions: ['*'] }
            ], currentMode); // Use 'file' or 'directory' mode

            if (!inputPath) {
                outputDiv.innerHTML = '<p class="text-gray-400">Choose cancelled.</p>';
                return;
            }
            outputDiv.innerHTML = '<p class="text-lg text-gray-400">Parsing log file(s)...</p>';
            
            const modeFlag = currentMode === 'directory' ? '--dir' : '--file';
            const res = await window.electronAPI.analyzeStart(modeFlag, inputPath);
            if (!res || !res.success) throw new Error(res?.error || 'Analyzer failed');

            // v14: Filter the results to only show files with a deviceName
            const validFiles = res.analysisResults.filter(file => file.deviceName);

            if (validFiles.length === 0) {
                // Show a message if no valid device logs were found
                const fileOrDir = currentMode === 'directory' ? 'directory' : 'file';
                outputDiv.innerHTML = `<p class="text-lg text-yellow-400">⚠️ No valid device logs found in the selected ${fileOrDir}.</p>`;
                populateFileList([]); // Hide the sidebar
                return;
            }

            // Pass the *filtered* array of result objects to the file list
            populateFileList(validFiles);
            // handleFileSelect is called by populateFileList
            
        } catch (err) {
            console.error('Error parsing log file:', err);
            outputDiv.innerHTML = `<p class="text-lg text-red-500">❌ Error: ${err.message}</p>`;
        }
    });

    // EXPORT TO XLSX button
    xlsxFileInput.addEventListener('click', async () => {
        outputDiv.innerHTML = '<p class="text-lg text-gray-400">Choosing json file(s) to export...</p>';
        try {
            const inputPath = await window.electronAPI.openFileDialog('xlsx_input_path',[
                { name: 'Parsed Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ], currentMode); // Use 'file' or 'directory' mode

            if (!inputPath) {
                outputDiv.innerHTML = '<p class="text-gray-400">Choose cancelled.</p>';
                return;
            }
            outputDiv.innerHTML = '<p class="text-lg text-gray-400">Exporting file(s)...</p>';

            const res = await window.electronAPI.exportToExcel(inputPath, currentMode);
            if (!res || !res.success) throw new Error(res?.error || 'Export failed');
            
            // Show feedback in the main output div for the global button
            outputDiv.innerHTML = `✅ Export completed. Files saved to: ${res.result[0].outDir}`;
            
        } catch (err) {
            console.error('Error exporting file:', err);
            outputDiv.innerHTML = `<p class="text-lg text-red-500">❌ Error: ${err.message}</p>`;
        }
    });

    // --- Accordion Logic ---
    outputDiv.addEventListener('click', (event) => {
        const header = event.target.closest('h2.collapsible-header');
        if (!header) return;

        const content = header.nextElementSibling;
        if (content && content.classList.contains('collapsible-content')) {
            header.classList.toggle('collapsed');
            content.classList.toggle('collapsed');
        }
    });
});