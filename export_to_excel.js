const fs = require("fs");
const path = require("path");
const XLSX = require("xlsx");

const INPUT_DIR = path.join(process.cwd(), "output");

// --- Helpers ---

function safe(v) {
  return v === null || v === undefined ? "" : v;
}

function flatten(obj, prefix = "", out = {}) {
  for (const [k, v] of Object.entries(obj || {})) {
    const newKey = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "object" && !Array.isArray(v) && v !== null) {
      flatten(v, newKey, out);
    } else {
      out[newKey] = v;
    }
  }
  return out;
}

function extractProtocols(d) {
  const rows = [["Protocol", "Field", "Value"]];
  for (const [proto, content] of Object.entries(d.protocols || {})) {
    if (!content) continue;

    if (Array.isArray(content)) {
      content.forEach((item, i) => {
        const flat = flatten(item);
        for (const [k, v] of Object.entries(flat)) {
          rows.push([proto, `${i + 1}.${k}`, safe(v)]);
        }
      });
    } else if (typeof content === "object") {
      for (const [subkey, subval] of Object.entries(content)) {
        if (Array.isArray(subval)) {
          subval.forEach((el, j) => {
            const flat = flatten(el);
            for (const [k, v] of Object.entries(flat)) {
              rows.push([proto, `${subkey}[${j + 1}].${k}`, safe(v)]);
            }
          });
        } else if (typeof subval === "object") {
          const flat = flatten(subval);
          for (const [k, v] of Object.entries(flat)) {
            rows.push([proto, `${subkey}.${k}`, safe(v)]);
          }
        } else {
          rows.push([proto, subkey, safe(subval)]);
        }
      }
    } else {
      rows.push([proto, "", safe(content)]);
    }
  }
  return rows;
}

function makeMainSheet(deviceName, d) {
  const rows = [];

  // --- Summary ---
  rows.push(["Summary"]);
  rows.push(["Hostname", d.identity?.sysname || deviceName]);
  rows.push(["Uptime", d.software?.uptime || ""]);
  rows.push(["CPU Avg", d.resources?.cpu?.avg || ""]);
  rows.push(["Memory Usage", d.resources?.memory?.used_mb + " / " + d.resources?.memory?.total_mb + " MB"]);
  rows.push(["Total Power", (d.resources?.power?.reduce((s, p) => s + (p.total_w || 0), 0) || 0) + " W"]);
  rows.push(["Critical Alarms", (d.alarms || []).filter(a => /critical/i.test(a.severity)).length]);
  rows.push(["Active Interfaces", (d.interfaces || []).filter(i => /up/i.test(i.status)).length]);
  rows.push([]);
  rows.push([]);

  // --- Identity ---
  rows.push(["== Identity =="]);
  Object.entries(d.identity || {}).forEach(([k, v]) => rows.push([k, safe(v)]));
  rows.push([]);

  // --- Software ---
  rows.push(["== Software =="]);
  Object.entries(d.software || {}).forEach(([k, v]) => rows.push([k, safe(v)]));
  rows.push([]);

  // --- Resources ---
  rows.push(["== Resources =="]);
  Object.entries(d.resources || {}).forEach(([k, v]) => {
    if (typeof v === "object") {
      const flat = flatten(v);
      for (const [fk, fv] of Object.entries(flat)) rows.push([`${k}.${fk}`, safe(fv)]);
    } else {
      rows.push([k, safe(v)]);
    }
  });
  rows.push([]);

  // --- Hardware ---
  rows.push(["== Hardware =="]);
  (d.hardware?.cards || []).forEach(c => {
    rows.push(["Card", c.slot, c.type, c.status]);
  });
  (d.hardware?.sfp || []).forEach(s => {
    rows.push(["SFP", s.port, s.status, s.vendor_pn, s.rx_dbm, s.tx_dbm]);
  });
  rows.push([]);

  // --- Interfaces ---
  rows.push(["== Interfaces =="]);
  (d.interfaces || []).forEach(i => {
    rows.push([i.name, i.status, i.protocol, i.ip, i.mask, i.vpn_instance, i.bandwidth_mbps, i.duplex, i.description]);
  });
  rows.push([]);

  // --- Routing ---
  rows.push(["== Routing =="]);
  Object.entries(d.routing || {}).forEach(([k, v]) => rows.push([k, JSON.stringify(v)]));
  rows.push([]);

  // --- Licenses ---
  rows.push(["== Licenses =="]);
  (d.licenses || []).forEach(l => rows.push([l.item_name, l.used_value, l.control_value, l.description]));
  rows.push([]);

  // --- Alarms ---
  rows.push(["== Alarms =="]);
  (d.alarms || []).forEach(a => {
    rows.push([a.severity || a.level, a.state, a.date, a.time, a.description]);
  });

  return rows;
}

// --- Main Execution ---

(function main() {
  if (!fs.existsSync(INPUT_DIR)) {
    console.error("❌ ./output not found");
    process.exit(1);
  }

  const files = fs.readdirSync(INPUT_DIR).filter(f => f.endsWith(".json"));
  if (!files.length) {
    console.error("⚠️  No JSON files found in ./output/");
    process.exit(1);
  }

  for (const file of files) {
    const jsonPath = path.join(INPUT_DIR, file);
    const data = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
    const deviceName = data.identity?.sysname || path.basename(file, ".json");

    const wsMain = XLSX.utils.aoa_to_sheet(makeMainSheet(deviceName, data));
    const wsProtocols = XLSX.utils.aoa_to_sheet(extractProtocols(data));

    // --- Workbook ---
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, wsMain, deviceName.substring(0, 31));
    XLSX.utils.book_append_sheet(wb, wsProtocols, (deviceName + "_Protocols").substring(0, 31));

    const outPath = path.join(INPUT_DIR, `${path.basename(file, ".json")}.xlsx`);
    XLSX.writeFile(wb, outPath);
    console.log("✅ Excel created:", outPath);
  }
})();
