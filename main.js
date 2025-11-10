// main.js - v14
// - `analyze:start` now receives and forwards an array of { outputPath, deviceName } objects
//   to the renderer as `analysisResults`.

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
    const data = await fs.promises.readFile(settingsPath, 'utf8');
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

async function saveLastPaths() {
  try {
    await fs.promises.writeFile(settingsPath, JSON.stringify(lastPaths, null, 2), 'utf8');
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
    const dirPath = (mode === 'directory') ? selectedPath : path.dirname(selectedPath); 
    lastPaths[key] = dirPath;
    await saveLastPaths();
    return selectedPath;
});
    // Handle analyzer start
    ipcMain.handle('analyze:start', async (event,  mode, inputPath ) => {
        try {
            // This will be an array of { outputPath, deviceName } objects
            let analysisResults; 
            
            const analyzer = require('./analyzer');
            console.log(`Running analyzer on: ${inputPath} in mode: ${mode}`); // Debug log

            if (mode === '--file') {
                // analyzeFile now returns a single { outputPath, deviceName } object
                const analysisResult = await analyzer.analyzeFile(inputPath);
                analysisResults = [analysisResult]; // Wrap in an array
            } else {
                // analyzeDirectory now returns an array of { outputPath, deviceName } objects
                analysisResults = await analyzer.analyzeDirectory(inputPath);
            }

            console.log('Analyzer results:', analysisResults); // Debug log

            if (!analysisResults || analysisResults.length === 0) {
                 throw new Error("Analyzer finished but returned no valid output files.");
            }

            return { 
                success: true, 
                analysisResults: analysisResults // Pass the array of objects
            };
        } catch (error) {
            console.error('analyze:start error', error);
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
        const exportToExcel = require('./export_to_excel');
        let result; // This will be an array of result objects
        
        if (mode === 'file') {
          // exportOne returns a single { outDir, outPath } object
          const exportResult = await exportToExcel.exportOne(inputPath);
          result = [exportResult]; // Wrap in an array
        } else {
          // exportAll returns an array of { outDir, outPath } objects
          result = await exportToExcel.exportAll(inputPath); 
        }
        
        return { success: true, result }; // result is always an array
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
    width: 1200, // Wider for new UI
    height: 800, // Taller for new UI
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
      preload: path.join(__dirname, 'preload.js'),
      devTools: true
    }
  });

  // Load the interface HTML file
  mainWindow.loadFile(path.join(__dirname, 'interface/index.html')); // Assuming index.html is in root
  
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