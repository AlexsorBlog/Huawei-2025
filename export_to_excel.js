const fs = require("fs");
const path = require("path");
const XlsxPopulate = require("xlsx-populate");

const INPUT_DIR = path.join(process.cwd(), "output");

// ────────────── Helpers ──────────────
function safe(v) {
  return v === null || v === undefined ? "" : v;
}
function toV(v, unit = "") {
  if (v === null || v === undefined || v === "") return "";
  return unit ? `${v} ${unit}` : v;
}
function first(arr) {
  return Array.isArray(arr) && arr.length ? arr[0] : null;
}

function colorFor(value) {
  const v = String(value || "").toUpperCase();
  if (/(UP|OK|TRUE|GOOD)/.test(v)) return "C6EFCE"; // green
  if (/(DOWN|FAIL|FALSE|CRIT|ERROR)/.test(v)) return "F8CECC"; // red
  if (/(WARN|MINOR|ALARM|ISSUE)/.test(v)) return "FFF2CC"; // yellow
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
    let maxLen = 10;
    for (let r = 1; r <= endRow; r++) {
      const cell = sheet.cell(r, c);
      const val = cell.value();
      if (val != null && val !== "") {
        const len = String(val).length;
        if (len > maxLen) maxLen = len;
      }
    }
    sheet.column(c).width(Math.min(maxLen + 2, 60));
  }
}

function setHeader(sheet, row, values) {
  sheet.row(row).cell(1).value([values]);
  sheet.row(row).style({
    bold: true,
    fill: "D9D9D9",
    border: true,
    horizontalAlignment: "center",
  });
}

// ────────────── Sheet Builders ──────────────
function buildSummarySheet(sheet, d, name) {
  const mem = first(d.resources?.memory) || {};
  const cpu = first(d.resources?.cpu) || {};
  const totalW = (d.resources?.power || []).reduce((s, p) => s + (p.total_power_w || 0), 0);

  let row = 1;
  sheet.cell(`A${row}`).value(`Device Summary: ${name}`).style({ bold: true, fill: "BDD7EE" });
  row += 2;

  const summaryHeader = ["Field", "Value", "Field", "Value"];
  setHeader(sheet, row++, summaryHeader);

  const identity = [
    ["Hostname", d.identity?.sysname || name, "Model", d.identity?.model || ""],
    ["Version", d.software?.version || "", "Uptime", d.software?.uptime || ""],
    ["Router ID", d.identity?.router_id_public || "", "Timezone", d.identity?.timezone || ""],
    ["Current Time", d.identity?.current_time || "", "Patch", d.identity?.patch_status || ""],
    ["Serial", d.identity?.serial || "", "Config Saved", d.identity?.config_saved || ""],
  ];

  for (const vals of identity) sheet.row(row++).cell(1).value([vals]);

  row += 2;
  sheet.cell(`A${row}`).value("Resources").style({ bold: true, fill: "F2F2F2" });
  row++;

  const resData = [
    ["CPU Avg (%)", cpu.avg ?? "", "CPU Max (%)", cpu.max ?? ""],
    ["Mem Usage (%)", mem.usage_pct ?? "", "Cache (MB)", mem.cache_mb ?? ""],
    ["Total Power (W)", totalW || "", "", ""],
  ];
  for (const vals of resData) sheet.row(row++).cell(1).value([vals]);

  row += 2;
  sheet.cell(`A${row}`).value("Counts").style({ bold: true, fill: "F2F2F2" });
  row++;

  const countData = [
    ["Interfaces", d.interfaces?.length || 0, "SFPs", d.hardware?.sfp?.length || 0],
    ["Cards", d.hardware?.cards?.length || 0, "PICs", d.hardware?.pics?.length || 0],
    ["Alarms", d.alarms?.length || 0, "Licenses", d.licenses?.length || 0],
  ];
  for (const vals of countData) sheet.row(row++).cell(1).value([vals]);

  sheet.usedRange().style("border", true);
  sheet.usedRange().style("wrapText", true);
  autoFitColumns(sheet);
}

function buildInterfacesSheet(wb, d) {
  const sheet = wb.addSheet("Interfaces");
  const header = [
    "Interface Name", "Protocol", "Bandwidth(Mbps)", "Duplex",
    "Logic_status", "vpn-instance", "IP address", "IPv6 address", "Mask",
    "Description", "VLAN / Eth-Trunk #",
    "OSPF Area | ISIS process", "OSPF | ISIS cost",
    "OSPF MultiArea", "OSPF MultiArea cost",
    "Rx(dBm)", "Tx(dBm)"
  ];
  setHeader(sheet, 1, header);

  const interfaces = d.interfaces || d.data?.interfaces || []; // ✅ more robust source

  if (!interfaces.length) {
    sheet.cell("A2").value("⚠️ No interface data found").style({ italic: true, fill: "FFF2CC" });
    autoFitColumns(sheet);
    return;
  }

  let row = 2;
  for (const itf of interfaces) {
    const vals = [
      safe(itf.name), safe(itf.protocol), safe(itf.bandwidth_mbps), safe(itf.duplex),
      safe(itf.status), safe(itf.vpn_instance), safe(itf.ip), safe(itf.ipv6), safe(itf.mask),
      safe(itf.description),
      itf.vlan_id ? `VLAN ${itf.vlan_id}` : itf.eth_trunk ? `Eth-Trunk ${itf.eth_trunk}` : "",
      safe(itf.ospf_area || itf.isis_process),
      safe(itf.ospf_cost || itf.isis_cost),
      (itf.ospf_multiarea || []).join(" "),
      (itf.ospf_multiarea_cost || []).join(" "),
      safe(itf.rx_dbm), safe(itf.tx_dbm)
    ];

    sheet.row(row).cell(1).value([vals]);
    applyConditionalColor(sheet.cell(row, 5), itf.status);
    row++;
  }

  sheet.usedRange().style("border", true);
  autoFitColumns(sheet);
}


function buildRoutingSheet(wb, d) {
  const sheet = wb.addSheet("Routing");
  sheet.cell("A1").value("Routing & Protocols").style({ bold: true, fill: "BDD7EE" });
  let row = 3;

  const vrfHeader = ["VRF Name", "Router ID", "Address Family"];
  setHeader(sheet, row++, vrfHeader);

  for (const v of d.protocols?.vrfs || [])
    sheet.row(row++).cell(1).value([[v.name || "", v.router_id || "", Array.isArray(v.af) ? v.af.join(", ") : (v.af || "")]]);

  row += 2;
  const bgpHeader = ["BGP VRF", "Peer", "ASN", "State"];
  setHeader(sheet, row++, bgpHeader);

  for (const b of d.protocols?.bgp?.neighbors || []) {
    const vals = [b.vrf || "", b.neighbor || "", b.as ?? "", b.state || ""];
    sheet.row(row).cell(1).value([vals]);
    applyConditionalColor(sheet.cell(row, 4), b.state);
    row++;
  }

  row += 2;
  const ospfHeader = ["OSPF Area", "Interface", "Neighbor ID", "State"];
  setHeader(sheet, row++, ospfHeader);

  for (const o of d.protocols?.ospf?.neighbors || []) {
    const vals = [o.area || "", o.interface || "", o.neighbor_id || "", o.state || ""];
    sheet.row(row).cell(1).value([vals]);
    applyConditionalColor(sheet.cell(row, 4), o.state);
    row++;
  }

  sheet.usedRange().style("border", true);
  autoFitColumns(sheet);
}

function buildHardwareSheet(wb, d) {
  const sheet = wb.addSheet("Hardware");
  sheet.cell("A1").value("Hardware & Resources").style({ bold: true, fill: "BDD7EE" });
  let row = 3;

  const cardHeader = ["Slot", "Type", "Online", "Status", "Role"];
  setHeader(sheet, row++, cardHeader);

  for (const c of d.hardware?.cards || []) {
    const vals = [c.slot || "", c.type || "", c.online || "", c.status || "", c.role || ""];
    sheet.row(row).cell(1).value([vals]);
    applyConditionalColor(sheet.cell(row, 4), c.status);
    row++;
  }

  row += 2;
  const powerHeader = ["Slot", "Voltage(V)", "Current(A)", "Power(W)"];
  setHeader(sheet, row++, powerHeader);

  for (const p of d.resources?.power || [])
    sheet.row(row++).cell(1).value([[p.slot || "", toV(p.input_voltage_v), toV(p.input_current_a), toV(p.total_power_w)]]);

  row += 2;
  const sfpHeader = ["Port", "Status", "Rx(dBm)", "Tx(dBm)", "Wavelength(nm)", "Vendor"];
  setHeader(sheet, row++, sfpHeader);

  for (const s of d.hardware?.sfp || []) {
    const vals = [s.port || "", s.status || "", s.rx_dbm ?? "", s.tx_dbm ?? "", s.wavelength_nm ?? "", s.vendor_pn || ""];
    sheet.row(row).cell(1).value([vals]);
    applyConditionalColor(sheet.cell(row, 2), s.status);
    row++;
  }

  sheet.usedRange().style("border", true);
  autoFitColumns(sheet);
}

function buildAlarmsSheet(wb, d) {
  const sheet = wb.addSheet("Alarms & Lic");
  sheet.cell("A1").value("Alarms").style({ bold: true, fill: "BDD7EE" });

  const header = ["Severity", "State", "Date", "Time", "Description"];
  setHeader(sheet, 3, header);

  let row = 4;
  for (const a of d.alarms || []) {
    const vals = [a.severity || "", a.state || "", a.date || "", a.time || "", a.description || ""];
    sheet.row(row).cell(1).value([vals]);
    applyConditionalColor(sheet.cell(row, 1), a.severity);
    row++;
  }

  row += 2;
  sheet.cell(`A${row}`).value("Licenses").style({ bold: true, fill: "BDD7EE" });
  row += 2;

  const licHeader = ["Item", "Used", "Control", "Description"];
  setHeader(sheet, row++, licHeader);

  for (const l of d.licenses || []) {
    const vals = [l.item_name || "", l.used_value || "", l.control_value || "", l.description || ""];
    sheet.row(row).cell(1).value([vals]);
    row++;
  }

  sheet.usedRange().style("border", true);
  autoFitColumns(sheet);
}

// ────────────── Export Logic ──────────────
async function exportFile(jsonPath) {
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

  const outPath = path.join(INPUT_DIR, `${path.basename(jsonPath, ".json")}.xlsx`);
  await wb.toFileAsync(outPath);
  console.log("✅ Excel created:", outPath);
}
module.exports = exportFile;
// ────────────── Main ──────────────
(async () => {
  if (!fs.existsSync(INPUT_DIR)) {
    console.error("❌ ./output not found");
    process.exit(1);
  }
  const files = fs.readdirSync(INPUT_DIR).filter(f => f.toLowerCase().endsWith(".json"));
  if (!files.length) {
    console.error("⚠️ No JSON files found in ./output/");
    process.exit(1);
  }
  for (const f of files) await exportOne(path.join(INPUT_DIR, f));
})();
