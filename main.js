// main.js - Главный диспетчер Electron

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
// Setup IPC handlers once
let isIPCSetup = false;
const settingsPath = path.join(app.getPath('userData'), 'last_paths.json');
let lastPaths = {}; // Буфер для хранения путей в памяти

/**
 * Загружает сохраненные пути из файла.
 */
async function loadLastPaths() {
    try {
        const data = await fs.readFile(settingsPath, 'utf8');
        lastPaths = JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('Last paths file not found, starting fresh.');
        } else {
            console.error('Error loading last paths:', error);
        }
        lastPaths = {};
    }
}

/**
 * Сохраняет текущие пути в файл.
 */
async function saveLastPaths() {
    try {
        await fs.writeFile(settingsPath, JSON.stringify(lastPaths, null, 2), 'utf8');
    } catch (error) {
        console.error('Error saving last paths:', error);
    }
}
function setupIPC() {
    if (isIPCSetup) return;
    
    // Handle file dialog opening with proper filters
 ipcMain.handle('dialog:openFileOrDirectory', async (_, key, filters, mode) => {
    
    // 1. Объявляем effectiveFilters и options в общей области видимости (Scope)
    let effectiveFilters = filters;
    let properties = [];
    let options = {};
    const defaultPath = lastPaths[key];

    // --- Логика определения режима (properties) ---
    
    if (mode === 'directory') {
        properties = ['openDirectory']; // Только папка
        effectiveFilters = undefined; // Фильтры не нужны для папок
    } else { // mode === 'file' (по умолчанию)
        properties = ['openFile']; // Только файл
    }
    // 3. Создаем объект options (теперь он виден)
    options = {
        properties: properties,
        // Если effectiveFilters определен, используем его; иначе - не передаем filters
        ...(effectiveFilters && { filters: effectiveFilters }),
        ...(defaultPath && { defaultPath: defaultPath })
    };
    
    // 4. Вызов диалога (теперь options доступен)
    const result = await dialog.showOpenDialog(options);

    if (result.canceled) return null;
    
    const selectedPath = result.filePaths[0];
    
    // 5. Сохранение пути
    const dirPath = path.dirname(selectedPath); 
    lastPaths[key] = dirPath;
    await saveLastPaths();
    return selectedPath;
});
    // Handle analyzer start
    ipcMain.handle('analyze:start', async (event,  mode, inputPath ) => {
        try {
            // Execute the analyzer with the provided input file
            let result;
            
            // Execute the analyzer with the provided input file
            const analyzer = require('./analyzer');
            console.log('Running analyzer on:', inputPath); // Debug log

            if (mode === '--file') {
                // Присваиваем значение, НЕ используя const/let снова
                result = await analyzer.analyzeFile(inputPath);
            } else {
                // Присваиваем значение, НЕ используя const/let снова
                result = await analyzer.analyzeDirectory(inputPath);
            }

            // Теперь 'result' доступен здесь и имеет присвоенное значение
            console.log('Analyzer result:', result);// Debug log

            // Get the output file path (assuming it's in the output directory)
            const inputFileName = path.basename(inputPath, path.extname(inputPath));
            const outputPath = path.join(__dirname, 'output', `parsed_${inputFileName}.json`);
            console.log('Output will be saved to:', outputPath); // Debug log
            
            // Ensure output directory exists
            //if (!fs.existsSync(path.dirname(outputPath))) {
            //    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
            //}
            // Save the result to file
            //await fs.promises.writeFile(outputPath, JSON.stringify(result, null, 2));

            return { 
                success: true, 
                data: result,
                outputPath: outputPath
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    });

    // Read arbitrary file (used by renderer to open JSON files)
    ipcMain.handle('file:read', async (event, filePath) => {
        try {
            const content = await fs.promises.readFile(filePath, 'utf8');
            return { success: true, content };
        } catch (err) {
            console.error('file:read error', err);
            return { success: false, error: err.message };
        }
    });

    // Handle Excel export
    ipcMain.handle('export:excel', async (event, inputPath, mode) => {
        try {
            console.log('Path:', inputPath);
            let result
            // Execute the export_to_excel.js script
            const exportToExcel = require('./export_to_excel');
            if (mode === 'file') {
                // Присваиваем значение, НЕ используя const/let снова
                result = await exportToExcel.exportOne(inputPath);
            } else {
                // Присваиваем значение, НЕ используя const/let снова
                result = await exportToExcel.exportAll(inputPath);
            }
            console.log('Parsing result:', result);
            const inputFileName = path.basename(inputPath, path.extname(inputPath));
            const outputPath = path.join(__dirname, 'output', `${inputFileName}.xlsx`);
            console.log('Output will be saved to:', outputPath); // Debug log
            // Ensure output directory exists
            /*if (!fs.existsSync(outputDir)) {
                fs.mkdirSync(outputDir, { recursive: true });
            }
            */
            // Execute the export script with the provided JSON file
            return { success: true, message: 'Excel file has been created successfully' };
        } catch (err) {
            console.error('export:excel error', err);
            return { success: false, error: err.message };
        }
    });

    isIPCSetup = true;
}

function createWindow () {
  // Create the main application window
  const mainWindow = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
      preload: path.join(__dirname, 'preload.js'),
      devTools: true
    }
  });

  // Load the interface HTML file
  mainWindow.loadFile(path.join(__dirname, 'interface', 'index.html'));
  
  // Prevent any automatic file operations on startup
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('app-ready');
  });
}
app.whenReady().then(async () => {
    await loadLastPaths();
    setupIPC();  // Setup IPC handlers first
    createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});