const { contextBridge, ipcRenderer } = require('electron');
const path = require('path');

contextBridge.exposeInMainWorld('electronAPI', {
    // Expose path module for path operations in renderer
    path: {
        join: path.join,
        dirname: path.dirname,
        basename: path.basename
    },
    // Для вызова проводника/файлового диалога
    // openFileDialog accepts an optional array of filters: [{ name, extensions: [...] }]
    openFileDialog: (filters) => ipcRenderer.invoke('dialog:openFileOrDirectory', filters), 
    
    // Для вызова Вашего анализатора (передаем режим и путь)
    analyzeStart: (mode, inputPath) => ipcRenderer.invoke('analyze:start', mode, inputPath),
    
    // Прочитать файл (JSON viewer)
    readFile: (filePath) => ipcRenderer.invoke('file:read', filePath),
    
    // Export to Excel
    exportToExcel: (inputPath) => ipcRenderer.invoke('export:excel', inputPath)
});