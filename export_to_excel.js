// export_to_excel.js
const fs = require("fs");
const path = require("path");
const XlsxPopulate = require("xlsx-populate");

// ───────────────── helpers: path + fs ─────────────────
function isDevElectronExecPath(p) {
  return /node_modules[\\\/]electron[\\\/]dist/i.test(p || "");
}

/**
 * Decide where to save files:
 * - Portable build: PORTABLE_EXECUTABLE_DIR (electron-builder sets this)
 * - Packaged EXE: dirname(process.execPath)
 * - Dev (npm start): use process.cwd()
 */
function resolveBaseDir() {
  if (process.env.PORTABLE_EXECUTABLE_DIR) return process.env.PORTABLE_EXECUTABLE_DIR;

  const exeDir = path.dirname(process.execPath || "");
  if (isDevElectronExecPath(exeDir)) return process.cwd(); // npm start

  return exeDir || process.cwd();
}

/**
 * Ensure directory exists. Returns true if OK, false if failed.
 */
function ensureDir(p) {
  try {
    fs.mkdirSync(p, { recursive: true });
    return true;
  } catch (e) {
    console.error("⚠️ ensureDir failed:", p, e.message);
    return false;
  }
}

/**
 * Try to open a file for write to detect permission quickly.
 */
function canWriteDir(dir) {
  try {
    const test = path.join(dir, ".write-test.tmp");
    fs.writeFileSync(test, "ok");
    fs.unlinkSync(test);
    return true;
  } catch {
    return false;
  }
}

/**
 * Decide the final output directory:
 * 1) Prefer "<EXE or cwd>/output"
 * 2) Fallback to "%APPDATA%/<AppName>/output" (userData-like) if not writable
 *    (no electron import; we infer a name)
 */
function getOutputDir() {
  const base = resolveBaseDir();
  const primary = path.join(base, "output");
  if (ensureDir(primary) && canWriteDir(primary)) {
    console.log("📦 Output dir:", primary, "(primary)");
    return primary;
  }

  // Fallback to user profile (Windows/Linux/macOS safe)
  const appName = "Huawei-Analyzer";
  const home = process.env.APPDATA || process.env.HOME || process.cwd();
  const fallback = path.join(home, appName, "output");

  ensureDir(fallback);
  console.log("📦 Output dir:", fallback, "(fallback)");
  return fallback;
}

// Common small helpers you already use
function safe(v) { return v == null ? "" : v; }
function toV(v, unit = "") { return v == null || v === "" ? "" : unit ? `${v} ${unit}` : v; }
function first(a) { return Array.isArray(a) && a.length ? a[0] : null; }
function colorFor(value) {
  const v = String(value || "").toUpperCase();
  if (/(UP|OK|TRUE|GOOD)/.test(v)) return "C6EFCE";
  if (/(DOWN|FAIL|FALSE|CRIT|ERROR)/.test(v)) return "F8CECC";
  if (/(WARN|MINOR|ALARM|ISSUE)/.test(v)) return "FFF2CC";
  return null;
}
function applyConditionalColor(cell, value) {
  const color = colorFor(value);
  if (color) cell.style("fill", color);
}
function autoFitColumns(sheet) {
  const range = sheet.usedRange();
  if (!range) return;
  const endCol = range.endCell().columnNumber();
  const endRow = range.endCell().rowNumber();
  for (let c = 1; c <= endCol; c++) {
    let max = 10;
    for (let r = 1; r <= endRow; r++) {
      const val = sheet.cell(r, c).value();
      if (val) max = Math.max(max, String(val).length);
    }
    sheet.column(c).width(Math.min(max + 2, 60));
  }
}
function setHeader(sheet, row, vals) {
  sheet.row(row).cell(1).value([vals]);
  sheet.row(row).style({
    bold: true,
    fill: "D9D9D9",
    border: true,
    horizontalAlignment: "center",
  });
}

// ───────────────── the sheet builders (unchanged) ─────────────────
function buildSummarySheet(sheet, d, name) {
  const mem = first(d.resources?.memory) || {};
  const cpu = first(d.resources?.cpu) || {};
  const totalW = (d.resources?.power || []).reduce((s, p) => s + (p.total_power_w || 0), 0);

  let r = 1;
  sheet.cell(`A${r}`).value(`Device Summary: ${name}`).style({ bold: true, fill: "BDD7EE" });
  r += 2;

  setHeader(sheet, r++, ["Field", "Value", "Field", "Value"]);
  const idRows = [
    ["Hostname", d.identity?.sysname || name, "Model", d.identity?.model || ""],
    ["Version", d.software?.version || "", "Uptime", d.software?.uptime || ""],
    ["Router ID", d.identity?.router_id_public || "", "Timezone", d.identity?.timezone || ""],
    ["Current Time", d.identity?.current_time || "", "Patch", d.identity?.patch_status || ""],
    ["Serial", d.identity?.serial || "", "Config Saved", d.identity?.config_saved || ""],
  ];
  idRows.forEach(v => sheet.row(r++).cell(1).value([v]));

  r += 2;
  sheet.cell(`A${r}`).value("Resources").style({ bold: true, fill: "F2F2F2" });
  r++;
  const res = [
    ["CPU Avg (%)", cpu.avg ?? "", "CPU Max (%)", cpu.max ?? ""],
    ["Mem Usage (%)", mem.usage_pct ?? "", "Cache (MB)", mem.cache_mb ?? ""],
    ["Total Power (W)", totalW || "", "", ""],
  ];
  res.forEach(v => sheet.row(r++).cell(1).value([v]));

  r += 2;
  sheet.cell(`A${r}`).value("Counts").style({ bold: true, fill: "F2F2F2" });
  r++;
  const count = [
    ["Interfaces", d.interfaces?.length || 0, "SFPs", d.hardware?.sfp?.length || 0],
    ["Cards", d.hardware?.cards?.length || 0, "PICs", d.hardware?.pics?.length || 0],
    ["Alarms", d.alarms?.length || 0, "Licenses", d.licenses?.length || 0],
  ];
  count.forEach(v => sheet.row(r++).cell(1).value([v]));

  sheet.usedRange().style("border", true);
  sheet.usedRange().style("wrapText", true);
  autoFitColumns(sheet);
}

function buildInterfacesSheet(wb, d) {
  const sh = wb.addSheet("Interfaces");
  const head = [
    "Interface Name","Protocol","Bandwidth(Mbps)","Duplex",
    "Logic_status","vpn-instance","IP address","IPv6 address","Mask",
    "Description","VLAN / Eth-Trunk #","OSPF Area | ISIS process",
    "OSPF | ISIS cost","OSPF MultiArea","OSPF MultiArea cost","Rx(dBm)","Tx(dBm)"
  ];
  setHeader(sh, 1, head);
  const ifs = d.interfaces || d.data?.interfaces || [];
  if (!ifs.length) {
    sh.cell("A2").value("⚠️ No interface data found").style({ italic:true, fill:"FFF2CC" });
    autoFitColumns(sh); return;
  }
  let r=2;
  for (const itf of ifs) {
    const v=[
      safe(itf.name),safe(itf.protocol),safe(itf.bandwidth_mbps),safe(itf.duplex),
      safe(itf.status),safe(itf.vpn_instance),safe(itf.ip),safe(itf.ipv6),safe(itf.mask),
      safe(itf.description),
      itf.vlan_id?`VLAN ${itf.vlan_id}`:itf.eth_trunk?`Eth-Trunk ${itf.eth_trunk}`:"",
      safe(itf.ospf_area||itf.isis_process),
      safe(itf.ospf_cost||itf.isis_cost),
      (itf.ospf_multiarea||[]).join(" "),
      (itf.ospf_multiarea_cost||[]).join(" "),
      safe(itf.rx_dbm),safe(itf.tx_dbm)
    ];
    sh.row(r).cell(1).value([v]);
    applyConditionalColor(sh.cell(r,5),itf.status);
    r++;
  }
  sh.usedRange().style("border",true);
  autoFitColumns(sh);
}

function buildRoutingSheet(wb,d){
  const sh=wb.addSheet("Routing");
  sh.cell("A1").value("Routing & Protocols").style({bold:true,fill:"BDD7EE"});
  let r=3;
  setHeader(sh,r++,["VRF Name","Router ID","Address Family"]);
  for(const v of d.protocols?.vrfs||[])
    sh.row(r++).cell(1).value([[v.name||"",v.router_id||"",Array.isArray(v.af)?v.af.join(", "):(v.af||"")]]);
  r+=2; setHeader(sh,r++,["BGP VRF","Peer","ASN","State"]);
  for(const b of d.protocols?.bgp?.neighbors||[]){
    const vals=[b.vrf||"",b.neighbor||"",b.as??"",b.state||""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r,4),b.state); r++;
  }
  r+=2; setHeader(sh,r++,["OSPF Area","Interface","Neighbor ID","State"]);
  for(const o of d.protocols?.ospf?.neighbors||[]){
    const vals=[o.area||"",o.interface||"",o.neighbor_id||"",o.state||""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r,4),o.state); r++;
  }
  sh.usedRange().style("border",true);
  autoFitColumns(sh);
}

function buildHardwareSheet(wb,d){
  const sh=wb.addSheet("Hardware");
  sh.cell("A1").value("Hardware & Resources").style({bold:true,fill:"BDD7EE"});
  let r=3;
  setHeader(sh,r++,["Slot","Type","Online","Status","Role"]);
  for(const c of d.hardware?.cards||[]){
    const vals=[c.slot||"",c.type||"",c.online||"",c.status||"",c.role||""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r,4),c.status); r++;
  }
  r+=2; setHeader(sh,r++,["Slot","Voltage(V)","Current(A)","Power(W)"]);
  for(const p of d.resources?.power||[])
    sh.row(r++).cell(1).value([[p.slot||"",toV(p.input_voltage_v),toV(p.input_current_a),toV(p.total_power_w)]]);
  r+=2; setHeader(sh,r++,["Port","Status","Rx(dBm)","Tx(dBm)","Wavelength(nm)","Vendor"]);
  for(const s of d.hardware?.sfp||[]){
    const vals=[s.port||"",s.status||"",s.rx_dbm??"",s.tx_dbm??"",s.wavelength_nm??"",s.vendor_pn||""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r,2),s.status); r++;
  }
  sh.usedRange().style("border",true);
  autoFitColumns(sh);
}

function buildAlarmsSheet(wb,d){
  const sh=wb.addSheet("Alarms & Lic");
  sh.cell("A1").value("Alarms").style({bold:true,fill:"BDD7EE"});
  setHeader(sh,3,["Severity","State","Date","Time","Description"]);
  let r=4;
  for(const a of d.alarms||[]){
    const vals=[a.severity||"",a.state||"",a.date||"",a.time||"",a.description||""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r,1),a.severity); r++;
  }
  r+=2; sh.cell(`A${r}`).value("Licenses").style({bold:true,fill:"BDD7EE"}); r+=2;
  setHeader(sh,r++,["Item","Used","Control","Description"]);
  for(const l of d.licenses||[]){
    const vals=[l.item_name||"",l.used_value||"",l.control_value||"",l.description||""];
    sh.row(r).cell(1).value([vals]); r++;
  }
  sh.usedRange().style("border",true);
  autoFitColumns(sh);
}

// ───────────────── export API ─────────────────
async function exportOne(jsonPath) {
  const outDir = getOutputDir(); // logs where we save
  const data = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  const deviceName = data.identity?.sysname || path.basename(jsonPath, ".json");

  const wb = await XlsxPopulate.fromBlankAsync();
  const sheet = wb.sheet(0);
  sheet.name("Summary");

  buildSummarySheet(sheet, data, deviceName);
  buildInterfacesSheet(wb, data);
  buildRoutingSheet(wb, data);
  buildHardwareSheet(wb, data);
  buildAlarmsSheet(wb, data);

  const outPath = path.join(outDir, `${path.basename(jsonPath, ".json")}.xlsx`);
  await wb.toFileAsync(outPath);
  console.log("✅ Excel created:", outPath);

  return { outDir, outPath };
}

async function exportAll(dir) {
  const outDir = getOutputDir(); // ensures existence and logs
  const src = dir || outDir; // if no dir passed, use output dir (JSONs usually there)
  const files = fs.readdirSync(src).filter(f => f.toLowerCase().endsWith(".json"));
  if (!files.length) throw new Error(`No JSON files found in: ${src}`);
  const results = [];
  for (const f of files) results.push(await exportOne(path.join(src, f)));
  return results;
}

module.exports = { exportOne, exportAll };

// ───────────────── CLI (optional) ─────────────────
if (require.main === module) {
  (async () => {
    try {
      console.log("BASE:", resolveBaseDir());
      console.log("USING:", getOutputDir());
      await exportAll(); // will default to output dir near exe/cwd
    } catch (e) {
      console.error("❌", e.stack || e.message);
      process.exit(1);
    }
  })();
}
