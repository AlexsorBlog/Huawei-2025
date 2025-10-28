// main.js - Главный диспетчер Electron

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
// Setup IPC handlers once
let isIPCSetup = false;

function setupIPC() {
    if (isIPCSetup) return;
    
    // Handle file dialog opening with proper filters
    ipcMain.handle('dialog:openFileOrDirectory', async (event, filters) => {
        const options = {
            properties: ['openFile'],
            filters: filters || [
                { name: 'Text Files', extensions: ['txt'] },
                { name: 'Log Files', extensions: ['log'] },
                { name: 'JSON Files', extensions: ['json'] },
                { name: 'All Files', extensions: ['*'] }
            ]
        };
        const result = await dialog.showOpenDialog(options);
        if (result.canceled) return null;
        return result.filePaths[0];
    });

    // Handle analyzer start
    ipcMain.handle('analyze:start', async (event,  mode,inputPath ) => {
        try {
            // Execute the analyzer with the provided input file
            const analyzer = require('./analyzer');
            console.log('Running analyzer on:', inputPath); // Debug log
            const result = await analyzer(inputPath, mode );
            console.log('Analyzer result:', result); // Debug log

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
    ipcMain.handle('export:excel', async (event, inputPath) => {
        try {
            console.log('Path:', inputPath);
            // Execute the export_to_excel.js script
            const exportToExcel = require('./export_to_excel');
            const result = await exportToExcel(inputPath);
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
app.whenReady().then(() => {
    setupIPC();  // Setup IPC handlers first
    createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});