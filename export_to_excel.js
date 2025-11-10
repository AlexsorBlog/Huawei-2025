// export_to_excel.js (v11)
// - Added new sheet "EVPN-VXLAN"
// - Added LSR-ID, SSH Users to Summary
// - Added ISIS, BGP EVPN, BGP Config Peers to Routing
const fs = require("fs");
const path = require("path");
const XlsxPopulate = require("xlsx-populate");

// ───────────────── helpers: path + fs ─────────────────
function isDevElectronExecPath(p) {
  return /node_modules[\\\/]electron[\\\/]dist/i.test(p || "");
}

function resolveBaseDir() {
  if (process.env.PORTABLE_EXECUTABLE_DIR) return process.env.PORTABLE_EXECUTABLE_DIR;

  const exeDir = path.dirname(process.execPath || "");
  if (isDevElectronExecPath(exeDir)) return process.cwd(); // npm start

  return exeDir || process.cwd();
}

function ensureDir(p) {
  try {
    fs.mkdirSync(p, { recursive: true });
    return true;
  } catch (e) {
    console.error("⚠️ ensureDir failed:", p, e.message);
    return false;
  }
}

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

// Common small helpers
function safe(v) { return v == null ? "" : v; }
function toV(v, unit = "") { return v == null || v === "" ? "" : unit ? `${v} ${unit}` : v; }
function first(a) { return Array.isArray(a) && a.length ? a[0] : null; }
function colorFor(value) {
  const v = String(value || "").toUpperCase();
  if (/(UP|OK|TRUE|GOOD|MASTER|NORMAL|PRESENT|FULL)/.test(v)) return "C6EFCE";
  if (/(DOWN|FAIL|FALSE|CRIT|ERROR|SLAVE|ABNORMAL)/.test(v)) return "F8CECC";
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

// ───────────────── sheet builders ─────────────────
function buildSummarySheet(sheet, d, name) {
  const mem = first(d.resources?.memory) || {};
  const cpu = first(d.resources?.cpu) || {};
  const totalW = (d.resources?.power || []).reduce((s, p) => s + (p.total_power_w || 0), 0);
  const sshUsers = (d.identity?.ssh_users || []).map(u => u.name).join(' / ');

  let r = 1;
  sheet.cell(`A${r}`).value(`Device Summary: ${name}`).style({ bold: true, fill: "BDD7EE" });
  r += 2;

  setHeader(sheet, r++, ["Field", "Value", "Field", "Value"]);
  const idRows = [
    ["Hostname", d.identity?.hostname || name, "Model", d.identity?.model || ""],
    ["Version", d.software?.version || "", "Uptime", d.software?.uptime || ""],
    ["Router ID", d.identity?.router_id_public || "", "LSR ID", d.identity?.lsr_id || ""],
    ["Current Time", d.identity?.current_time || "", "Patch", d.identity?.patch_status || ""],
    ["Serial", d.identity?.serial || "", "Config Saved", d.identity?.config_saved || ""],
    ["SSH Users", sshUsers, "", ""],
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
    ["Eth-Trunks", d.protocols?.trunks?.eth_trunks?.length || 0, "E-Trunks", d.protocols?.trunks?.e_trunks?.length || 0],
    ["VXLAN VNIs", d.protocols?.vxlan?.vnis?.length || 0, "EVPN Instances", d.protocols?.evpn?.instances?.length || 0],
  ];
  count.forEach(v => sheet.row(r++).cell(1).value([v]));

  sheet.usedRange().style("border", true);
  sheet.usedRange().style("wrapText", true);
  autoFitColumns(sheet);
}

function buildInterfacesSheet(wb, d) {
  const sh = wb.addSheet("Interfaces");
  const head = [
    "Interface Name", "Phy_status", "Logic_status", "Bandwidth(Mbps)", "Duplex",
    "vpn-instance", "IP address", "IPv6 address", "Mask",
    "Description", "VLAN / Eth-Trunk #", "OSPF Area | ISIS process",
    "OSPF | ISIS cost", "OSPF MultiArea", "OSPF MultiArea cost", "Rx(dBm)", "Tx(dBm)"
  ];
  setHeader(sh, 1, head);
  const ifs = d.interfaces || d.data?.interfaces || [];
  if (!ifs.length) {
    sh.cell("A2").value("⚠️ No interface data found").style({ italic: true, fill: "FFF2CC" });
    autoFitColumns(sh); return;
  }
  let r = 2;
  for (const itf of ifs) {
    const v = [
      safe(itf.name),
      safe(itf.status),         // Phy_status
      safe(itf.protocol),      // Logic_status
      safe(itf.bandwidth_mbps),
      safe(itf.duplex),
      safe(itf.vpn_instance),
      safe(itf.ip),
      safe(itf.ipv6),
      safe(itf.mask),
      safe(itf.description),
      itf.vlan_id ? `VLAN ${itf.vlan_id}` : itf.eth_trunk ? `Eth-Trunk ${itf.eth_trunk}` : "",
      safe(itf.ospf_area || itf.isis_process),
      safe(itf.ospf_cost || itf.isis_cost),
      (itf.ospf_multiarea || []).join(" "),
      (itf.ospf_multiarea_cost || []).join(" "),
      safe(itf.rx_dbm),
      safe(itf.tx_dbm)
    ];
    sh.row(r).cell(1).value([v]);
    applyConditionalColor(sh.cell(r, 2), itf.status);   // Color Phy_status
    applyConditionalColor(sh.cell(r, 3), itf.protocol); // Color Logic_status
    r++;
  }
  sh.usedRange().style("border", true);
  autoFitColumns(sh);
}

function buildRoutingSheet(wb, d) {
  const sh = wb.addSheet("Routing");
  sh.cell("A1").value("Routing & Protocols").style({ bold: true, fill: "BDD7EE" });
  let r = 3;
  
  setHeader(sh, r++, ["VRF Name", "Router ID", "Address Family"]);
  for (const v of d.protocols?.vrfs || [])
    sh.row(r++).cell(1).value([[v.name || "", v.router_id || "", Array.isArray(v.af) ? v.af.join(", ") : (v.af || "")]]);
  
  r += 2; setHeader(sh, r++, ["BGP VRF", "Peer", "ASN", "State"]);
  for (const b of d.protocols?.bgp?.neighbors || []) {
    const vals = [b.vrf || "", b.neighbor || "", b.as ?? "", b.state || ""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 4), b.state); r++;
  }
  
  r += 2; setHeader(sh, r++, ["BGP EVPN Peer", "ASN", "State", "Uptime", "Routes"]);
  for (const b of d.protocols?.bgp?.evpn_peers || []) {
      const vals = [b.neighbor || "", b.as || "", b.state || "", b.uptime || "", b.routes || 0];
      sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 3), b.state); r++;
  }
  
  r += 2; setHeader(sh, r++, ["BGP Config Peer", "Local AS", "Peer AS", "Description", "BFD Enabled"]);
  for (const b of d.protocols?.bgp?.config_peers || []) {
      const vals = [b.peer_ip || "", b.local_as || "", b.peer_as || "", b.description || "", b.bfd || false];
      sh.row(r).cell(1).value([vals]); r++;
  }

  r += 2; setHeader(sh, r++, ["OSPF Area", "Interface", "Neighbor ID", "State"]);
  for (const o of d.protocols?.ospf?.neighbors || []) {
    const vals = [o.area || "", o.interface || "", o.neighbor_id || "", o.state || ""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 4), o.state); r++;
  }
  
  r += 2; setHeader(sh, r++, ["ISIS Process ID", "Network Entity", "IS Level"]);
  for (const i of d.protocols?.isis?.processes || []) {
    const vals = [i.id || "", i.network_entity || "", i.is_level || ""];
    sh.row(r).cell(1).value([vals]); r++;
  }
  
  r += 2; setHeader(sh, r++, ["Routing Proto", "Total", "Active", "Added", "Deleted", "Freed"]);
  for (const s of d.routing?.table_summary || []) {
      if (s.vrf) {
           sh.row(r).cell(1).value([[`VRF: ${s.vrf}`, s.total_routes || ""]]);
           sh.row(r).style({ bold: true, fill: "F2F2F2" }); r++;
      }
      if (Array.isArray(s.summary_prefixes)) {
          for (const p of s.summary_prefixes) {
              sh.row(r++).cell(1).value([[p.proto, p.total, p.active, p.added, p.deleted, p.freed]]);
          }
      } else if (s.summary_prefixes) {
          sh.row(r++).cell(1).value([["Summary", s.summary_prefixes]]);
      }
  }

  sh.usedRange().style("border", true);
  autoFitColumns(sh);
}

function buildHardwareSheet(wb, d) {
  const sh = wb.addSheet("Hardware");
  sh.cell("A1").value("Hardware & Resources").style({ bold: true, fill: "BDD7EE" });
  let r = 3;
  setHeader(sh, r++, ["Slot", "Type", "Online", "Status", "Role"]);
  for (const c of d.hardware?.cards || []) {
    const vals = [c.slot || "", c.type || "", c.online || "", c.status || "", c.role || ""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 4), c.status); r++;
  }
  r += 2; setHeader(sh, r++, ["Slot", "Voltage(V)", "Current(A)", "Power(W)"]);
  for (const p of d.resources?.power || [])
    sh.row(r++).cell(1).value([[p.slot || "", toV(p.input_voltage_v), toV(p.input_current_a), toV(p.total_power_w)]]);
  r += 2; setHeader(sh, r++, ["Port", "Status", "Rx(dBm)", "Tx(dBm)", "Wavelength(nm)", "Vendor"]);
  for (const s of d.hardware?.sfp || []) {
    const vals = [s.port || "", s.status || "", s.rx_dbm ?? "", s.tx_dbm ?? "", s.wavelength_nm ?? "", s.vendor_pn || ""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 2), s.status); r++;
  }
  sh.usedRange().style("border", true);
  autoFitColumns(sh);
}

function buildEvpnSheet(wb, d) {
  const sh = wb.addSheet("EVPN-VXLAN");
  sh.cell("A1").value("EVPN / VXLAN / Trunks").style({ bold: true, fill: "BDD7EE" });
  let r = 3;

  setHeader(sh, r++, ["Eth-Trunk ID", "Type", "State", "Mode", "Actor", "Partner"]);
  for (const t of d.protocols?.trunks?.eth_trunks || []) {
      const vals = [t.id || "", t.type || "", t.state || "", t.mode || t.work_mode || "", t.actor || "", t.partner || ""];
      sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 3), t.state); r++;
  }

  r += 2; setHeader(sh, r++, ["E-Trunk ID", "State", "Peer IP", "System ID"]);
  for (const t of d.protocols?.trunks?.e_trunks || []) {
      const vals = [t.id || "", t.state || "", t.peer_ip || "", t.system_id || ""];
      sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 2), t.state); r++;
  }
  
  r += 2; setHeader(sh, r++, ["EVPN VPN-Instance", "EVI", "VNI"]);
  for (const e of d.protocols?.evpn?.instances || []) {
      sh.row(r++).cell(1).value([[e.vpn_instance || "", e.evi || "", e.vni || ""]]);
  }
  
  r += 2; setHeader(sh, r++, ["VXLAN VNI", "BD ID", "Peer IP", "Interface", "State"]);
  for (const v of d.protocols?.vxlan?.vnis || []) {
      const vals = [v.vni || "", v.bd || "", v.peer_ip || "", v.iface || "", v.state || ""];
      sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 5), v.state); r++;
  }
  
  sh.usedRange().style("border", true);
  autoFitColumns(sh);
}


function buildAlarmsSheet(wb, d) {
  const sh = wb.addSheet("Alarms & Lic");
  sh.cell("A1").value("Alarms").style({ bold: true, fill: "BDD7EE" });
  setHeader(sh, 3, ["Severity", "State", "Date", "Time", "Description"]);
  let r = 4;
  for (const a of d.alarms || []) {
    const vals = [a.severity || "", a.state || "", a.date || "", a.time || "", a.description || ""];
    sh.row(r).cell(1).value([vals]); applyConditionalColor(sh.cell(r, 1), a.severity); r++;
  }
  r += 2; sh.cell(`A${r}`).value("Licenses").style({ bold: true, fill: "BDD7EE" }); r += 2;
  setHeader(sh, r++, ["Item", "Used", "Control", "Description"]);
  for (const l of d.licenses || []) {
    const vals = [l.item_name || "", l.used_value || "", l.control_value || "", l.description || ""];
    sh.row(r).cell(1).value([vals]); r++;
  }
  sh.usedRange().style("border", true);
  autoFitColumns(sh);
}

// ───────────────── export API ─────────────────
async function exportOne(jsonPath) {
  const outDir = getOutputDir(); // logs where we save
  const data = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  const deviceName = data.identity?.sysname || data.identity?.hostname || path.basename(jsonPath, ".json");

  const wb = await XlsxPopulate.fromBlankAsync();
  const sheet = wb.sheet(0);
  sheet.name("Summary");

  buildSummarySheet(sheet, data, deviceName);
  buildInterfacesSheet(wb, data);
  buildRoutingSheet(wb, data);
  buildHardwareSheet(wb, data);
  buildEvpnSheet(wb, data); // New sheet
  buildAlarmsSheet(wb, data);

  const outPath = path.join(outDir, `${path.basename(jsonPath, ".json")}.xlsx`);
  await wb.toFileAsync(outPath);
  console.log("✅ Excel created:", outPath);

  return { outDir, outPath };
}

function findParsedFilesRecursively(currentDir) {
    let logFiles = [];
    const items = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const item of items) {
        const fullPath = path.join(currentDir, item.name);

        if (item.isDirectory()) {
            logFiles = logFiles.concat(findParsedFilesRecursively(fullPath));
        } else if (item.isFile() && item.name.toLowerCase().endsWith(".json")) {
            logFiles.push(fullPath);
        }
    }
    return logFiles;
}

async function exportAll(dir) {
  const outDir = getOutputDir(); // ensures existence and logs
  const src = dir || outDir; // if no dir passed, use output dir (JSONs usually there)
  
  let files;
  // Check if `dir` is a directory or a file
  try {
      if (fs.statSync(src).isDirectory()) {
          files = findParsedFilesRecursively(src);
      } else if (fs.statSync(src).isFile() && src.toLowerCase().endsWith(".json")) {
          files = [src]; // It's a single file
      } else {
           throw new Error("Input path is not a .json file or a directory.");
      }
  } catch (e) {
      throw new Error(`Failed to read path: ${e.message}`);
  }

  if (!files || !files.length) throw new Error(`No .json files found in: ${dir}`);
  
  const results = [];
  for (const f of files) {
    const model = await exportOne(f);
    results.push(model);
  }

  return results;
}

module.exports = { exportOne, exportAll };

// ───────────────── CLI (optional) ─────────────────
if (require.main === module) {
  (async () => {
    try {
      console.log("BASE:", resolveBaseDir());
      console.log("USING:", getOutputDir());
      
      const getArg = (flag) => {
        const i = process.argv.indexOf(flag);
        return i >= 0 ? process.argv[i + 1] : null;
      };
      const DIR_PATH = getArg("--dir");
      const FILE_PATH = getArg("--file");

      if (DIR_PATH) {
          await exportAll(DIR_PATH);
      } else if (FILE_PATH) {
          await exportOne(FILE_PATH);
      } else {
          console.log("No --file or --dir specified, exporting all .json from default output dir...");
          await exportAll(); // will default to output dir near exe/cwd
      }
      
    } catch (e) {
      console.error("❌", e.stack || e.message);
      process.exit(1);
    }
  })();
}