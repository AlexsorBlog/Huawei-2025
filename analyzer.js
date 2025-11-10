/**
 * analyzer.js — Huawei VRP Universal Log Analyzer (v13)
 * ----------------------------------------------------
 * - FIX (v13): `analyzeFile` and `analyzeDirectory` now return an object:
 * { outputPath, deviceName } to allow the UI to filter out empty/invalid logs.
 * - FIX (v12): `analyzeFile` and `analyzeDirectory` now return the `outFile` paths.
 * - FIX (v11): Robust Hybrid Parsing.
 */

const fs = require("fs");
const path = require("path");

// ---------- Settings ----------
// ---------- Base directory & output resolver (EXE/Node safe) ----------
function isDevElectronExecPath(p) {
  return /node_modules[\\\/]electron[\\\/]dist/i.test(p || "");
}

function resolveBaseDir() {
  if (process.env.PORTABLE_EXECUTABLE_DIR) return process.env.PORTABLE_EXECUTABLE_DIR;

  const exeDir = path.dirname(process.execPath || "");
  if (isDevElectronExecPath(exeDir)) return process.cwd(); // dev mode
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

  const appName = "Huawei-Analyzer";
  const home = process.env.APPDATA || process.env.HOME || process.cwd();
  const fallback = path.join(home, appName, "output");
  ensureDir(fallback);
  console.log("📦 Output dir:", fallback, "(fallback)");
  return fallback;
}

// ---------- Settings ----------
const BASE_DIR = resolveBaseDir();
const DEFAULT_FILE = path.join(BASE_DIR, "CommonCollectResult.txt");
const MARKER = "=========######HUAWEI#####=========";
const OUT_DIR = getOutputDir();

// Regex for commands, supporting abbreviations like 'dis cur'
const COMMAND_REGEX = /^(?:<[^>]+>|\[~?[^\]]+\])?\s*(dis(?:play)?\s+[a-z0-9\-]+(?:[\s\.][a-z0-9\-]+)*)/im;
// Regex to detect a raw config file (starts with #, !, or sysname)
const RAW_CONFIG_REGEX = /^(#|!Software Version|sysname|clock timezone)/im;


// ---------- CLI ----------
const getArg = (flag) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : null;
};
const DIR_PATH = getArg("--dir");
const FILE_PATH = getArg("--file");
const DIR_MODE = !!DIR_PATH;

// ---------- Utils ----------
const ensureOutDir = () => ensureDir(OUT_DIR);
const outPathFor = (inFile) =>
  path.join(OUT_DIR, "parsed_" + path.basename(inFile, path.extname(inFile)) + ".json");

const cleanTailPrompt = (s) =>
  s.replace(/\r/g, "").replace(/\n<[^>]+>\s*$/m, "").trim();

const toInt = (v) => {
  const n = parseInt(String(v || "").replace(/[^0-9\-]/g, ""), 10);
  return Number.isFinite(n) ? n : null;
};
const toFloat = (v) => {
  const n = parseFloat(String(v || "").replace(/[^0-9.\-]/g, ""));
  return Number.isFinite(n) ? n : null;
};
// Helper to dedupe arrays of objects by a key
const uniqBy = (arr, key) => {
    const seen = new Set();
    return (arr || []).filter(item => {
        const k = item[key];
        if (seen.has(k)) {
            return false;
        }
        seen.add(k);
        return true;
    });
};
const uniq = (arr) => [...new Set(arr || [])];
const lower = (s) => String(s || "").toLowerCase();
const normalizeKey = (s) => String(s || "").replace(/[^a-z0-9]+/gi, "_").toLowerCase();
const lines = (block) => (block || "").split(/\r?\n/);

// ---------- Block splitting / command detection ----------
function splitBlocks(raw) {
  if (raw.includes(MARKER)) {
    return raw.split(MARKER).map((s) => s.trim()).filter(Boolean);
  }
  // fallback heuristic if no markers
  // Use non-capturing groups (?:...) to prevent 'split' from adding 'undefined'
  return raw.split(/\n(?=<[^>]+>)|(?=^dis(?:play)?\s+)/im).map((s) => s.trim()).filter(Boolean);
}
function detectCommand(block) {
  for (const l of lines(block)) {
    const t = l.trim();
    if (!t) continue;
    if (/^<.*>$/.test(t) || /^\[~?.*]$/.test(t)) continue; // Prompt
    if (/^(Info|Warning|Error):/i.test(t)) continue; // System messages
    
    // Check for abbreviated or full display commands
    const cmdMatch = t.match(/^(dis(?:play)?\s+[a-z0-9\-]+(?:[\s\.][a-z0-9\-]+)*)/i);
    if (cmdMatch && cmdMatch[1]) return cmdMatch[1];
    
    if (
      /^(interface|controller|return|system|diagnose|bgp|ospf|isis|mpls|segment-routing|ip\s+route|ipsec|vxlan|evpn|vlan|eth-trunk|lacp|bfd|vrrp|lldp|vrf|vpn-instance|clock|ntp|patch|dir\s+cfcard)/i.test(
        t
      )
    )
      return t;
    if (/display/i.test(t)) return t; // Failsafe
    return t; // Return first non-empty, non-prompt line
  }
  return "unknown";
}
/**
 * Strips the command prompt from a block of text.
 * e.g., "<ta1-kie003>dis cur" becomes "!Software Version..."
 */
function stripCommandFromBlock(block) {
    const linesArr = lines(block);
    if (linesArr.length <= 1) return block;
    
    // Check if the first line is a command prompt
    if (COMMAND_REGEX.test(linesArr[0])) {
        return linesArr.slice(1).join('\n').trim(); // Return block without first line
    }
    return block; // Not a command block, return as-is
}

// ---------- Model ----------
function newModel() {
  return {
    identity: {
      hostname: null,
      sysname: null,
      model: null,               // e.g., "NetEngine 8000 M4"
      version: null,             // software version (pure)
      serial: null,              // ESN
      lsr_id: null,
      router_id_public: null,    // LoopBack0/public
      router_ids: {},            // { vrfName: routerId }
      timezone: null,            // full TZ string (e.g., "Europe/Kiev add 02:00:00")
      current_time: null,        // parsed from display clock
      patch_status: null,        // "none" or exact phrase ("Info: No patch exists.")
      config_saved: null,        // saved-configuration path/time if present
      ssh_users: [],             // [{ name, auth_type, service_type, rsa_key }]
      mac_addrs: { chassis: null, base: null }
    },
    software: { version: null, uptime: null },

    ntp: { state: null, stratum: null, servers: [] }, // servers: [{ ip, vpn_instance }]

    resources: {
      cpu: [],         // [{ avg,max,ts,per_service:[{name,pct}] }]
      memory: [],      // [{ used_mb,total_mb,free_mb,phys_total_mb,cache_mb,usage_pct }]
      disk: [],        // [{ source,total_kb,free_kb,used_kb }]
      power: [],       // [{ slot,input_voltage_v,input_current_a,total_power_w }]
      temperature: [], // [{ pcb,slot,status,temp_c }]
      fan: []          // [{ status, speeds: [{id,speed_percent}] }]
    },

    hardware: {
      cards: [],       // [{ slot,type,online,register,status,role }]
      pics: [],        // [{ pic,status,type,port_count,init_result,logic_down }]
      elabels: [],     // [{ scope,slot,manufacturer,part_number,barcode,item,description,model }]
      sfp: []          // [{ port,status,type,rx_dbm,tx_dbm,wavelength_nm,vendor_pn }]
    },

    interfaces: [],     // [{ name,status,protocol,ip,mask,ipv6,vpn_instance,bandwidth_mbps,duplex,description,rx_dbm,tx_dbm }]

    protocols: {
      mac: [],         // [{ vlan,mac,interface,type }]
      arp: [],         // [{ ip,mac,interface,expire,type,vpn }]
      vlans: [],       // [{ id,name,type,vxlan_vni,members:[] }]
      trunks: { eth_trunks: [], e_trunks: [] }, // [{ type:'Eth-Trunk|E-Trunk|LACP',id,mode,state,members:[], ...}]
      lldp: { enabled: null, neighbors: [] }, // neighbors optional
      vrrp: { enabled: null, groups: [] },
      bfd: { sessions: [], config: {}, reflector: {} },
      ospf: { neighbors: [], areas: [], router_ids: {} },
      isis: { neighbors: [], areas: [], processes: [] }, // processes: [{ id, network_entity, is_level }]
      bgp: { neighbors: [], vpnv4: [], vpnv6: [], evpn_peers: [], config_peers: [] }, // config_peers: [{ peer_ip, local_as, peer_as, description, bfd }]
      vrfs: [],        // [{ name, af:['ipv4','ipv6'], router_id }]
      mpls: { ldp: {}, te: {}, sr: { srgb: null, srlb: null, lsp_stats: { srbe: null } } },
      evpn: { instances: [] }, // instances: [{ vpn_instance, evi, vni }]
      vxlan: { vnis: [] } // vnis: [{ vni, bd, peer_ip, iface, state }]
    },

    routing: {
      table_summary: [], // [{ vrf,total_routes,summary_prefixes:[{proto, total, active,...}] }]
      static: []         // [{ vrf,prefix,mask,next_hop,iface }]
    },

    licenses: [],        // [{ sale_name,item_name,control_value,used_value,description }]
    alarms: [],          // [{ sequence,level,severity,state,date,time,description,interface }]
    raw_sections: {}     // { normalizedCmd: [ {raw, error?} ] } for diagnostics
  };
}

// ---------- Interface map helper ----------
function ensureInterface(model, name) {
  const key = lower(name || "");
  if (!key) return null; // Don't create interfaces for empty names
  if (!ensureInterface._map) ensureInterface._map = new Map();
  const map = ensureInterface._map;
  let idx = map.get(key);
  if (idx === undefined) {
    idx = model.interfaces.length;
    model.interfaces.push({ name });
    map.set(key, idx);
  }
  return model.interfaces[idx];
}

// ---------- Parsers (identity/software/clock/patch/ntp/licenses) ----------
function p_display_version(b, model) {
  const txt = cleanTailPrompt(b);
  const verMatch = txt.match(/VRP.*?Version\s*([^\n\r]+)/i) || txt.match(/Version\s*([^\n\r]+)/i);
  if (verMatch && verMatch[1]) {
    const v = verMatch[1].trim();
    const pure = v.replace(/\(.*?\)\s*$/, "").trim();
    model.software.version = pure || v;
    model.identity.version = model.software.version;
  }
  const upMatch = txt.match(/uptime\s+is\s*([^\n\r]+)/i);
  if (upMatch && upMatch[1]) model.software.uptime = upMatch[1].trim();

  // try to extract model independently & cleanly
  const modMatch =
    txt.match(/NetEngine\s+([^\n\r]+?)(?:\s+uptime|\)|$)/i) ||
    txt.match(/Device\s+Type\s*[:]\s*([^\n\r]+)/i);
  if (modMatch && modMatch[1]) {
      const modelStr = ("NetEngine " + modMatch[1].trim())
          .replace(/NetEngine NetEngine/i, "NetEngine")
          .replace(/V800R0.*$/i, "").trim();
      model.identity.model = modelStr;
  }
}

function p_display_router_id(b, model) {
  // "RouterID: 172.x.x.x"
  const m = b.match(/RouterID\s*:\s*([0-9.]+)/i);
  if (m && m[1]) model.identity.router_id_public = m[1];
}

function p_display_mpls_lsr_id(b, model) {
    // "LSR ID       : x.x.x.x"
    const m = b.match(/LSR\s+ID\s*:\s*([0-9.]+)/i);
    if (m && m[1]) model.identity.lsr_id = m[1];
}

function p_display_router_id_vrf(b, model) {
  // "display router id vpn-instance NAME" -> "RouterID: x.x.x.x"
  const nameMatch = b.match(/vpn-instance\s+([^\n\r]+)/i);
  const ridMatch = b.match(/RouterID\s*:\s*([0-9.]+)/i);
  const name = nameMatch ? nameMatch[1].trim() : null;
  const rid = ridMatch ? ridMatch[1].trim() : null;
  
  if (name && rid) {
    model.identity.router_ids[name] = rid;
    // also ensure it exists in protocols.vrfs
    const idx = model.protocols.vrfs.findIndex(v => v.name === name);
    if (idx >= 0) model.protocols.vrfs[idx].router_id = rid;
    else model.protocols.vrfs.push({ name: name, af: null, router_id: rid });
  }
}

function p_display_clock(b, model) {
  const head = lines(b)[0] || "";
  if (/\d{4}-\d{2}-\d{2}/.test(head)) model.identity.current_time = head.trim();
  const tzMatch =
    b.match(/Time\s*Zone\s*\(([^)]+)\)/i) ||
    b.match(/Time\s*Zone\s*:\s*([^\n\r]+)/i) ||
    b.match(/time\s*zone\s*:\s*([^\n\r]+)/i);
  if (tzMatch && tzMatch[1]) model.identity.timezone = tzMatch[1].trim();
}

function p_display_patch_information(b, model) {
  if (/No\s+patch\s+exists/i.test(b)) {
    model.identity.patch_status = "Info: No patch exists.";
    return;
  }
  const stMatch =
    b.match(/current state is\s*[: ]\s*([^\n\r]+)/i) ||
    b.match(/patch.*state\s*[:]\s*([^\n\r]+)/i);
  if (stMatch && stMatch[1]) model.identity.patch_status = stMatch[1].trim();
}

function p_display_startup(b, model) {
  const cfgMatch = (b.match(/Startup saved-configuration file\s*:\s*([^\n\r]+)/i) || [])[1];
  if (cfgMatch) model.identity.config_saved = cfgMatch.trim();
}

function p_display_ntp_status(b, model) {
  const stateMatch = b.match(/clock status\s*:\s*(\S+)/i);
  if (stateMatch && stateMatch[1]) model.ntp.state = stateMatch[1];
  const stratumMatch = b.match(/clock stratum\s*:\s*(\d+)/i);
  if (stratumMatch && stratumMatch[1]) model.ntp.stratum = toInt(stratumMatch[1]);
  // sometimes shows current servers too; capture any IPs
  const ips = [...b.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)].map(m => m[1]);
  if (ips.length) {
      const newServers = ips.map(ip => ({ ip, vpn_instance: null }));
      model.ntp.servers = uniqBy([...(model.ntp.servers || []), ...newServers], 'ip');
  }
}
function p_display_ntp_unicast(b, model) {
  const ips = [...b.matchAll(/ntp\s+unicast-?server\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+vpn-instance\s+(\S+))?/gi)];
  if (ips.length) {
      const newServers = ips.map(m => ({ ip: m[1], vpn_instance: m[2] || null }));
      model.ntp.servers = uniqBy([...(model.ntp.servers || []), ...newServers], 'ip');
  }
}

// licenses
function p_display_license_esn(b, model) {
  const esnMatch = (b.match(/ESN\s*:\s*([^\s\r\n]+)/i) || [])[1];
  if (esnMatch) model.identity.serial = esnMatch.trim();
}
function p_display_license_verbose(b, model) {
  const txt = cleanTailPrompt(b);
  const parts = txt.split(/\n(?=Sale\s+name)|(?=^Sale\s+name)/im).filter(p => /Sale\s+name/i.test(p));
  for (const p of parts) {
    const saleMatch = p.match(/Sale\s+name\s*:\s*(.*)/i);
    const itemMatch = p.match(/Item\s+name\s*:\s*(.*)/i);
    const controlMatch = p.match(/Control\s+value\s*:\s*(.*)/i);
    const usedMatch = p.match(/Used\s+value\s*:\s*(.*)/i);
    const descMatch = p.match(/Description\s*:\s*([\s\S]*?)(?:\n\n|$)/i);
    
    model.licenses.push({
      sale_name: saleMatch ? saleMatch[1].trim() : "",
      item_name: itemMatch ? itemMatch[1].trim() : "",
      control_value: controlMatch ? controlMatch[1].trim() : "",
      used_value: usedMatch ? usedMatch[1].trim() : "",
      description: descMatch ? descMatch[1].replace(/\s+/g, " ").trim() : ""
    });
  }
}

// ---------- Resources (CPU/memory/disk/power/temp/fan/alarms) ----------
function p_display_cpu_usage(b, model) {
  const entry = {};
  const sysMatch = b.match(/System cpu use rate is\s*:?\s*(\d+)%/i);
  if (sysMatch && sysMatch[1]) entry.avg = toInt(sysMatch[1]);
  
  const avgMatch = b.match(/five seconds\s*:\s*(\d+)%/i) || b.match(/5\s*sec.*?(\d+)%/i);
  if (avgMatch && avgMatch[1] && entry.avg == null) entry.avg = toInt(avgMatch[1]);
  
  const maxMatch = b.match(/max.*?(\d+)%/i);
  if (maxMatch && maxMatch[1]) entry.max = toInt(maxMatch[1]);
  
  const tsMatch = b.match(/time\s*[: ]\s*([0-9\-: ]{10,})/i);
  if (tsMatch && tsMatch[1]) entry.ts = tsMatch[1].trim();
  
  // per-service
  const per = [];
  for (const m of b.matchAll(/^\s*([A-Za-z0-9_\-\/]+)\s+(\d+)%/gm)) {
    if (!/System|five|max|CPU/i.test(m[1])) per.push({ name: m[1], pct: toInt(m[2]) });
  }
  if (per.length) entry.per_service = per;
  if (Object.keys(entry).length) model.resources.cpu.push(entry);
}

function p_display_health_verbose(b, model) {
  const usedTotalMatch = b.match(/Used\/Total\s*\(\s*([0-9.]+)\s*MB\s*\/\s*([0-9.]+)\s*MB\s*\)/i);
  const physMatch = b.match(/Physical\s+Free\/Total\s*\(\s*([0-9.]+)\s*MB\s*\/\s*([0-9.]+)\s*MB\s*\)/i);
  const cacheMatch = b.match(/Cache\s*\(\s*([0-9.]+)\s*MB\s*\)/i);
  const usagePctMatch = b.match(/Memory\s+Usage\s*\(\%\)\s*:\s*(\d+)/i);
  
  if (usedTotalMatch || physMatch || cacheMatch) {
    model.resources.memory.push({
      used_mb: usedTotalMatch ? toFloat(usedTotalMatch[1]) : null,
      total_mb: usedTotalMatch ? toFloat(usedTotalMatch[2]) : null,
      free_mb: physMatch ? toFloat(physMatch[1]) : null,
      phys_total_mb: physMatch ? toFloat(physMatch[2]) : null,
      cache_mb: cacheMatch ? toFloat(cacheMatch[1]) : null,
      usage_pct: usagePctMatch ? toInt(usagePctMatch[1]) : null
    });
  }
}

function p_dir_cfcard(b, model) {
  // "Total: 13,238,234 KB, Free: 9,194,587 KB"
  const m = b.match(/Total:\s*([0-9,]+)\s*KB,\s*Free:\s*([0-9,]+)\s*KB/i);
  if (m && m[1] && m[2]) {
    const total = toInt(m[1]);
    const free = toInt(m[2]);
    model.resources.disk.push({ source: "cfcard", total_kb: total, free_kb: free, used_kb: total - free });
  }
}

function p_display_power_any(b, model) {
  const slotMatch =
    b.match(/(?:Device|Power|Slot)\s*[: ]\s*(\d+)/i) ||
    b.match(/Power\s+Board\s+(\d+)/i);
  const voltMatch = b.match(/Input\s*Voltage\s*:\s*([0-9.]+)\s*V/i) || b.match(/InputVoltage\s*:\s*([0-9.]+)/i);
  const currMatch = b.match(/Input\s*Current\s*:\s*([0-9.]+)\s*A/i) || b.match(/InputCurrent\s*:\s*([0-9.]+)/i);
  const wattMatch = b.match(/Total\s*Power\s*:\s*([0-9.]+)\s*W/i) || b.match(/TotalPower\s*:\s*([0-9.]+)/i);
  
  const entry = {
    slot: slotMatch ? slotMatch[1].trim() : null,
    input_voltage_v: voltMatch ? toFloat(voltMatch[1]) : null,
    input_current_a: currMatch ? toFloat(currMatch[1]) : null,
    total_power_w: wattMatch ? toFloat(wattMatch[1]) : null
  };
  if (Object.values(entry).some(v => v !== null)) model.resources.power.push(entry);
}

function p_display_temperature(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (!t) continue;
    if (/^Base-Board|^PCB|^\-+|^Sensor|^Location|^display\s+temperature/i.test(t)) continue;
    const tokens = t.split(/\s+/);
    if (tokens.length < 2) continue;
    
    const last = tokens[tokens.length - 1];
    if (/^-?\d+$/.test(last) && tokens[0] && !/^[-]+$/.test(tokens[0])) {
      const statusMatch = t.match(/(NORMAL|MINOR|MAJOR|FATAL)/i);
      model.resources.temperature.push({
        pcb: tokens[0],
        slot: /^\d+$/.test(tokens[1]) ? tokens[1] : null,
        status: statusMatch ? statusMatch[1].toUpperCase() : null,
        temp_c: toInt(last)
      });
    }
  }
}

function p_display_fan(b, model) {
  const statusMatch = (b.match(/Status\s*:\s*([A-Za-z0-9_]+)/i) || [])[1];
  const speeds = [...b.matchAll(/\[(\d+)\]\s*(\d+)%/g)].map(m => ({ id: toInt(m[1]), speed_percent: toInt(m[2]) }));
  if (statusMatch || speeds.length) {
      model.resources.fan.push({ status: statusMatch || null, speeds });
  }
}

function p_display_alarm_all(b, model) {
  const txt = cleanTailPrompt(b);
  // try table lines first
  for (const ln of lines(txt)) {
    const m = ln.match(/^\s*(\d+)\s+(\w+)\s+(\d{4}-\d{2}-\d{2})\s+(\S+)\s+(.*)$/);
    if (m) {
      model.alarms.push({
        sequence: toInt(m[1]),
        level: m[2],
        severity: m[2], // Use level as severity
        date: m[3],
        time: m[4],
        description: m[5].trim(),
        state: 'active' // Assume active if in this table
      });
    }
  }
  // fallback: verbose chunks
  const chunks = txt.split(/\n\s*\n/).filter(Boolean);
  for (const c of chunks) {
    if (/Sequence\s*:/i.test(c)) {
      const descMatch = c.match(/Description\s*:\s*([\s\S]*)/i);
      model.alarms.push({
        sequence: toInt(c.match(/Sequence\s*:\s*(\d+)/i)?.[1]),
        alarm_id: c.match(/AlarmId\s*:\s*(\S+)/i)?.[1] || null,
        name: c.match(/AlarmName\s*:\s*(\S+)/i)?.[1] || null,
        severity: c.match(/Severity\s*:\s*(\S+)/i)?.[1] || null,
        state: c.match(/State\s*:\s*(\S+)/i)?.[1] || null,
        start_time: c.match(/StartTime\s*:\s*([^\n\r]+)/i)?.[1] || null,
        description: (descMatch ? descMatch[1] : "").replace(/\s+/g, " ").trim()
      });
    }
  }
}

// ---------- Hardware / Inventory ----------
function p_display_device(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (/^\d+\s+/.test(t)) {
      const p = t.split(/\s{2,}|\s+/).filter(Boolean);
      if (p.length >= 6) {
        model.hardware.cards.push({
          slot: p[0],
          type: p[1],
          online: p[2],
          register: p[3],
          status: p[4],
          role: p[5]
        });
      }
    }
  }
}
function p_display_device_pic_status(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (/^\d+\/\d+\s+/.test(t)) {
      const p = t.split(/\s{2,}|\s+/).filter(Boolean);
      if (p.length >= 6) {
        model.hardware.pics.push({
          pic: p[0], status: p[1], type: p[2], port_count: p[3], init_result: p[4], logic_down: p[5]
        });
      }
    }
  }
}
function p_display_elabel(b, model) {
  const scopeMatch =
    (b.match(/Elabel\s+of\s+([^\n\r]+)/i) || [])[1] ||
    (b.match(/Device\s*:\s*([^\n\r]+)/i) || [])[1] ||
    (b.match(/Board\s*:\s*([^\n\r]+)/i) || [])[1];
  const slotMatch = (b.match(/Slot\s*[: ]\s*(\d+)/i) || [])[1];
  const mfrMatch = (b.match(/(?:Manufacturer|VendorName)\s*[: ]\s*([^\n\r]+)/i) || [])[1];
  const pnMatch =
    (b.match(/Part\s*Number\s*[: ]\s*([^\n\r]+)/i) || [])[1] ||
    (b.match(/Item\s*[: ]\s*([^\n\r]+)/i) || [])[1];
  const bcMatch = (b.match(/BarCode\s*[: ]\s*([^\n\r]+)/i) || [])[1];
  const descMatch = (b.match(/Description\s*[: ]\s*([^\n\r]+)/i) || [])[1];
  const mdlMatch = (b.match(/Model\s*[: ]\s*([^\n\r]+)/i) || [])[1];

  model.hardware.elabels.push({
    scope: scopeMatch ? scopeMatch.trim() : "unknown",
    slot: slotMatch ? toInt(slotMatch) : null,
    manufacturer: mfrMatch ? mfrMatch.trim() : null,
    part_number: pnMatch ? pnMatch.trim() : null,
    barcode: bcMatch ? bcMatch.trim() : null,
    item: pnMatch ? pnMatch.trim() : null,
    description: descMatch ? descMatch.trim() : null,
    model: mdlMatch ? mdlMatch.trim() : null
  });

  const chassisMatch = (b.match(/Chassis\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  const baseMatch = (b.match(/Base\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  if (chassisMatch) model.identity.mac_addrs.chassis = chassisMatch.toLowerCase();
  if (baseMatch) model.identity.mac_addrs.base = baseMatch.toLowerCase();
}

function p_display_optical_module_any(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (!t) continue;
    let m =
      t.match(
        /^(\S+)\s+(\S+)\s+(\S+)\s+([\-]?\d+(?:\.\d+)?)(?:\s*dBm)?\s+([\-]?\d+(?:\.\d+)?)(?:\s*dBm)?\s+(\d{4,5})\s+(\S+)$/i
      ) ||
      t.match(
        /^(\S+)\s+(\S+)\s+(\S+)\s+([\-]?\d+(?:\.\d+)?dBm)\s+([\-]?\d+(?:\.\d+)?dBm)\s+(\S+)(?:\s+(\d{4,5}))?$/i
      );
    if (m) {
      let [_, port, status, type, rxS, txS, wlOrPn, pnOrWl] = m;
      let wavelength = null, vendor = null;
      if (/^\d{4,5}$/.test(wlOrPn) && pnOrWl) { wavelength = wlOrPn; vendor = pnOrWl; }
      else if (pnOrWl && /^\d{4,5}$/.test(pnOrWl)) { vendor = wlOrPn; wavelength = pnOrWl; }
      else { vendor = wlOrPn; }
      model.hardware.sfp.push({
        port, status, type,
        rx_dbm: toFloat(rxS),
        tx_dbm: toFloat(txS),
        wavelength_nm: wavelength ? toInt(wavelength) : null,
        vendor_pn: vendor || null
      });
      continue;
    }
    const wlMatch = t.match(/(\d{4,5})\s*nm/i);
    if (wlMatch && wlMatch[1]) {
      const port = t.split(/\s+/)[0];
      model.hardware.sfp.push({ port, wavelength_nm: toInt(wlMatch[1]) });
    }
  }
}

// ---------- Interfaces ----------
function p_display_interface_brief(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (/^(GigabitEthernet|X?GE|Eth|100GE|25GE|40GE|10GE|LoopBack|Ethernet|NULL|Vlanif)/i.test(t)) {
      const p = t.split(/\s{2,}/).map(s => s.trim()).filter(Boolean);
      if (p.length >= 3) {
        const itf = ensureInterface(model, p[0]);
        if (itf) {
            itf.status = p[1]; // Phy
            itf.protocol = p[2]; // Logic
            if (p[3]) itf.in_util = p[3];
            if (p[4]) itf.out_util = p[4];
        }
      }
    }
  }
}
function p_display_interface_ethernet_brief(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    const name = t.split(/\s+/)[0];
    const m = t.match(/\s(half|full)\s+(\d+)([MG])/i);
    if (name && m && m[1] && m[2] && m[3]) {
      const itf = ensureInterface(model, name);
      if (itf) {
          itf.duplex = m[1].toUpperCase();
          const num = toInt(m[2]); const unit = m[3].toUpperCase();
          itf.bandwidth_mbps = unit === "G" ? num * 1000 : num;
      }
    }
  }
}
function p_display_ip_interface(b, model) {
  const blk = cleanTailPrompt(b);
  for (const part of blk.split(/\n(?=Interface\s*:)/i)) {
    const nameMatch = part.match(/Interface\s*:\s*(\S+)/i);
    if (!nameMatch || !nameMatch[1]) continue;
    
    const itf = ensureInterface(model, nameMatch[1]);
    if (itf) {
        const ipv4Match = part.match(/IP\s*Address\s*:\s*([0-9.]+)\s+([0-9.]+)/i);
        if (ipv4Match && ipv4Match[1] && ipv4Match[2]) { itf.ip = ipv4Match[1]; itf.mask = ipv4Match[2]; }
        
        const vpnMatch = part.match(/VPN-Instance\s*:\s*([^\n\r]+)/i);
        if (vpnMatch && vpnMatch[1]) itf.vpn_instance = vpnMatch[1].trim();
    }
  }
}

// ---------- display current-configuration (THE BIG ONE) ----------
function p_display_current_configuration(b, model) {
  const txt = cleanTailPrompt(b);

  // !Software Version...
  const verMatch = txt.match(/^!Software Version\s+(.*)/im);
  if (verMatch && verMatch[1]) {
      model.software.version = verMatch[1].trim();
      model.identity.version = verMatch[1].trim();
  }
  
  // sysname
  const sysMatch = txt.match(/^\s*sysname\s+([^\s\r\n]+)/im);
  if (sysMatch && sysMatch[1]) model.identity.sysname = sysMatch[1];

  // clock timezone
  const tzMatch = txt.match(/^\s*clock\s+timezone\s+(.*)/im);
  if (tzMatch && tzMatch[1]) model.identity.timezone = tzMatch[1].trim();

  // ntp-service
  for (const m of txt.matchAll(/^\s*ntp-service\s+unicast-server\s+([0-9.]+)(?:\s+vpn-instance\s+(\S+))?/gim)) {
      model.ntp.servers.push({ ip: m[1], vpn_instance: m[2] || null });
  }

  // ssh users
  for (const m of txt.matchAll(/^\s*ssh\s+user\s+([^\s\r\n]+)([\s\S]*?)(?=\n\s*ssh\s+user|\n#)/gim)) {
      if (!m[1]) continue;
      const userBlock = m[2] || "";
      const authMatch = userBlock.match(/^\s*ssh\s+user\s+.*?\s+authentication-type\s+(\S+)/im);
      const serviceMatch = userBlock.match(/^\s*ssh\s+user\s+.*?\s+service-type\s+(\S+)/im);
      const rsaMatch = userBlock.match(/^\s*ssh\s+user\s+.*?\s+assign\s+rsa-key\s+(\S+)/im);
      model.identity.ssh_users.push({
          name: m[1],
          auth_type: authMatch ? authMatch[1] : null,
          service_type: serviceMatch ? serviceMatch[1] : null,
          rsa_key: rsaMatch ? rsaMatch[1] : null
      });
  }

  // VRFs (vpn-instance) and router-id inside block
  for (const m of txt.matchAll(/^\s*vpn-instance\s+([^\s\r\n]+)([\s\S]*?)(?=\n#)/gim)) {
    const name = m[1];
    const window = m[2] || "";
    const ridMatch = window.match(/router-id\s+([0-9.]+)/i);
    const af = [];
    if (/ipv4-family/i.test(window)) af.push("ipv4");
    if (/ipv6-family/i.test(window)) af.push("ipv6");
    const entry = { name, af: af.length ? af : null, router_id: ridMatch ? ridMatch[1] : null };
    
    const idx = model.protocols.vrfs.findIndex(v => v.name === name);
    if (idx >= 0) model.protocols.vrfs[idx] = { ...model.protocols.vrfs[idx], ...entry };
    else model.protocols.vrfs.push(entry);
    if (ridMatch && ridMatch[1]) model.identity.router_ids[name] = ridMatch[1];
  }

  // Router-ID public via LoopBack0
  const loBlkMatch = txt.match(/interface\s+LoopBack0([\s\S]*?)(?=\n#)/i);
  if (loBlkMatch && loBlkMatch[1]) {
    const loIPMatch = loBlkMatch[1].match(/ip\s+address\s+([0-9.]+)\s+[0-9.]+/i);
    if (loIPMatch && loIPMatch[1]) model.identity.router_id_public = loIPMatch[1];
  }

  // LLDP / VRRP flags (status)
  if (/^(?:\s*)lldp\s+enable/im.test(txt)) model.protocols.lldp.enabled = true;
  if (/^(?:\s*)vrrp\b/im.test(txt)) model.protocols.vrrp.enabled = true;

  // Static routes
  for (const m of txt.matchAll(/^\s*ip\s+route-static\s+([0-9.]+)\s+([0-9.]+|\d+)\s+([0-9.]+)(?:\s+(\S+))?/gim)) {
    model.routing.static.push({ vrf: null, prefix: m[1], mask: m[2], next_hop: m[3], iface: m[4] || null });
  }

  // Interfaces: enrich description, IP, IPv6, VRF, bandwidth
  const ifaceBlocks = txt.split(/\n(?=interface\s+)/i).filter(s => /^interface\s+/i.test(s.trim()));
  for (const blk of ifaceBlocks) {
    const firstLine = lines(blk)[0] || "";
    const name = firstLine.replace(/^interface\s+/i, "").trim();
    if (!name) continue;
    
    const itf = ensureInterface(model, name);
    if (!itf) continue;
    
    const descMatch = blk.match(/^\s*description\s+(.+)$/im);
    if (descMatch && descMatch[1]) itf.description = descMatch[1].trim();
    
    const ipv4Match = blk.match(/^\s*ip\s+address\s+([0-9.]+)\s+([0-9.]+|\d+)/im);
    if (ipv4Match && ipv4Match[1] && ipv4Match[2]) { itf.ip = ipv4Match[1]; itf.mask = ipv4Match[2]; }
    
    const ipv6Match = blk.match(/^\s*ipv6\s+address\s+([0-9a-fA-F:\/]+)/im);
    if (ipv6Match && ipv6Match[1]) itf.ipv6 = ipv6Match[1];
    
    const vrfMatch = blk.match(/^\s*(?:ip\s+binding|vpn-instance)\s+([^\s\r\n]+)/im);
    if (vrfMatch && vrfMatch[1]) itf.vpn_instance = vrfMatch[1];
    
    const bwMatch = blk.match(/^\s*(speed|bandwidth)\s+(\d+)(G|M|K)?/im);
    if (bwMatch && bwMatch[2]) {
      let val = toInt(bwMatch[2]); const unit = (bwMatch[3] || "M").toUpperCase();
      itf.bandwidth_mbps = unit === "G" ? val * 1000 : unit === "K" ? Math.round(val / 1000) : val;
    }
  }

  // MPLS SRGB/SRLB config (segment-routing)
  const srgbMatch = txt.match(/segment\-routing\s+global\-block\s+(\d+)\s+(\d+)/i);
  if (srgbMatch) model.protocols.mpls.sr.srgb = { start: toInt(srgbMatch[1]), end: toInt(srgbMatch[2]) };
  const srlbMatch = txt.match(/segment\-routing\s+local\-block\s+(\d+)\s+(\d+)/i);
  if (srlbMatch) model.protocols.mpls.sr.srlb = { start: toInt(srlbMatch[1]), end: toInt(srlbMatch[2]) };

  // ISIS (from config)
  for (const m of txt.matchAll(/^\s*isis(?:\s+(\d+))?([\s\S]*?)(?=\n#|\n!)/gim)) {
      const id = m[1] ? m[1].trim() : '1'; // Default process ID
      const block = m[2] || "";
      const netMatch = block.match(/network-entity\s+(\S+)/i);
      const levelMatch = block.match(/is-level\s+(\S+)/i);
      model.protocols.isis.processes.push({
          id: id,
          network_entity: netMatch ? netMatch[1] : null,
          is_level: levelMatch ? levelMatch[1] : null
      });
  }

  // BGP (from config)
  for (const m of txt.matchAll(/^\s*bgp(?:\s+(\d+))?([\s\S]*?)(?=\n#|\n!)/gim)) {
      const local_as = m[1] ? m[1].trim() : null;
      const block = m[2] || "";
      for (const p of block.matchAll(/peer\s+([0-9.]+)\s+as-number\s+(\d+)/gi)) {
          const peer_ip = p[1];
          const peer_as = p[2];
          const peerBlockRegex = new RegExp(`peer\\s+${peer_ip.replace(/\./g, '\\.')}([\\s\\S]*?)(?=\\n\\s*peer|\\n\\s*#|$)`, 'im');
          const peerBlockMatch = block.match(peerBlockRegex);
          const peerBlock = peerBlockMatch ? peerBlockMatch[1] : "";
          
          const descMatch = peerBlock.match(/description\s+(.+)/i);
          const bfdMatch = peerBlock.match(/bfd\s+enable/i);
          
          model.protocols.bgp.config_peers.push({
              peer_ip: peer_ip,
              local_as: local_as,
              peer_as: peer_as,
              description: descMatch ? descMatch[1].trim() : null,
              bfd: !!bfdMatch
          });
      }
  }
  
  // Alarms (from config)
  for (const m of txt.matchAll(/^\s*alarm([\s\S]*?)(?=\n#|\n!)/gim)) {
      const block = m[1] || "";
      for (const a of block.matchAll(/alarm-name\s+(\S+)\s+severity\s+(\S+)/gi)) {
          model.alarms.push({
              sequence: null,
              level: a[2],
              severity: a[2],
              date: null,
              time: null,
              description: a[1],
              state: 'Configured'
          });
      }
  }
}


// ---------- Protocols ----------
function p_display_arp_all(b, model) {
  let current = null;
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (/^\d{1,3}\.\d{1,3}\./.test(t)) {
      const parts = t.split(/\s{2,}|\s+/).filter(Boolean);
      const ip = parts[0], mac = parts[1] || "";
      let expire = "", type = "", iface = "", vpn = "";
      if (parts.length >= 5) { expire = parts[2]; type = parts[3]; iface = parts[4]; vpn = parts.slice(5).join(" "); }
      else if (parts.length === 4) { type = parts[2]; iface = parts[3]; }
      current = { ip, mac, interface: iface, expire, type, vpn };
      model.protocols.arp.push(current);
    } else if (current && t) {
      current.vpn = (current.vpn ? current.vpn + " " : "") + t;
    }
  }
}
function p_display_arp_statistics(b, model) {
  const totMatch = b.match(/Total\s*[: ]\s*(\d+)/i);
  const dynMatch = b.match(/Dynamic\s*[: ]\s*(\d+)/i);
  if (totMatch || dynMatch) model.protocols.arp.push({ stats: { total: toInt(totMatch?.[1]), dynamic: toInt(dynMatch?.[1]) } });
}

function p_display_mac_address_any(b, model) {
  for (const ln of lines(b)) {
    const m = ln.match(/^\s*(\d+)\s+([0-9a-fA-F.\-:]{12,})\s+(\S+)/);
    if (m) model.protocols.mac.push({ vlan: toInt(m[1]), mac: m[2].toLowerCase(), interface: m[3], type: "dynamic" });
  }
  const chassisMatch = (b.match(/Chassis\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  const baseMatch = (b.match(/Base\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  if (chassisMatch) model.identity.mac_addrs.chassis = chassisMatch.toLowerCase();
  if (baseMatch) model.identity.mac_addrs.base = baseMatch.toLowerCase();
}

function p_display_vlan(b, model) {
  const txt = cleanTailPrompt(b);
  const blocks = txt.split(/\n(?=VLAN\s+\d+)/i).filter(x => /VLAN\s+\d+/.test(x));
  for (const bl of blocks) {
    const idMatch = bl.match(/VLAN\s+(\d+)/i);
    const nameMatch = bl.match(/Name\s*:\s*([^\n\r]+)/i);
    const typeMatch = bl.match(/Type\s*:\s*([^\n\r]+)/i);
    const members = [...bl.matchAll(/(?:GE|Eth|XGE|100GE|25GE|40GE|10GE)\S+/g)].map(m => m[0]);
    model.protocols.vlans.push({ 
        id: idMatch ? toInt(idMatch[1]) : null, 
        name: nameMatch ? nameMatch[1].trim() : null, 
        type: typeMatch ? typeMatch[1].trim() : null, 
        members: uniq(members) 
    });
  }
}

function p_display_vxlan_vni_all(b, model) {
    for (const m of b.matchAll(/(\d+)\s+(\d+)\s+([0-9.]+)\s+(\S+)\s+(\S+)/g)) {
        if (/VNI/i.test(m[0])) continue; // Skip header
        model.protocols.vxlan.vnis.push({
            vni: toInt(m[1]),
            bd: toInt(m[2]),
            peer_ip: m[3],
            iface: m[4],
            state: m[5]
        });
    }
}
function p_display_evpn_vpn_instance(b, model) {
    for (const m of b.matchAll(/(\S+)\s+(\d+)\s+(\d+)/g)) {
         if (/VPN-Instance/i.test(m[0])) continue; // Skip header
         model.protocols.evpn.instances.push({
             vpn_instance: m[1],
             evi: toInt(m[2]),
             vni: toInt(m[3])
         });
    }
}

function p_display_eth_trunk(b, model) {
  let current = null;
  for (const ln of lines(b)) {
    const t = ln.trim();
    const headMatch = t.match(/^Eth-Trunk(\d+)\s+(\S+)\s+(\S+)/i); // ID, Mode, State
    if (headMatch && headMatch[1]) {
      current = { type: "Eth-Trunk", id: headMatch[1], work_mode: headMatch[2], state: headMatch[3], members: [] };
      model.protocols.trunks.eth_trunks.push(current);
      continue;
    }
    const memMatch = t.match(/Members?\s*in\s+trunk\s*(\d+)\s*:\s*(.+)$/im); // Members: ...
    if (memMatch && memMatch[2]) {
      const trunkId = memMatch[1];
      const target = model.protocols.trunks.eth_trunks.find(t => t.id === trunkId);
      if (target) {
          const ids = memMatch[2].match(/(?:GE|Eth|100GE|25GE|40GE|10GE)\S+/g) || [];
          target.members = uniq(ids);
      }
    }
    const masterMatch = t.match(/Master\s*State\s*:\s*(\S+)/i);
    if (current && masterMatch && masterMatch[1]) {
        current.master_state = masterMatch[1];
    }
  }
}

function p_display_e_trunk(b, model) {
    const idMatch = b.match(/E-TRUNK-ID\s*:\s*(\d+)/i);
    if (!idMatch) return; // Not a valid e-trunk block
    
    const stateMatch = b.match(/State\s*:\s*(\S+)/i);
    const peerMatch = b.match(/Peer-IP\s*:\s*([0-9.]+)/i);
    const sysIdMatch = b.match(/System-ID\s*:\s*(\S+)/i);
    
    model.protocols.trunks.e_trunks.push({
        id: idMatch[1],
        state: stateMatch ? stateMatch[1] : null,
        peer_ip: peerMatch ? peerMatch[1] : null,
        system_id: sysIdMatch ? sysIdMatch[1] : null
    });
}


function p_display_lacp_peer(b, model) {
  for (const ln of lines(b)) {
    const m = ln.match(/^Eth-Trunk(\d+)\s+(\S+)\s+Actor:\s*(\S+).*?Partner:\s*(\S+)/i);
    if (m) {
        const trunk = model.protocols.trunks.eth_trunks.find(t => t.id === m[1]);
        if (trunk) {
            trunk.type = "LACP";
            trunk.actor = m[3];
            trunk.partner = m[4];
        } else {
             model.protocols.trunks.eth_trunks.push({ type: "LACP", id: m[1], mode: m[2], actor: m[3], partner: m[4] });
        }
    }
  }
}

function p_display_bfd_session_all(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (/^\d/.test(t)) {
      const p = t.split(/\s{2,}/).filter(Boolean);
      if (p.length >= 4) {
        model.protocols.bfd.sessions.push({
          local: p[0], remote: p[1], peer_ip: p[2], state: p[3], type: p[4] || null, interface: p[5] || null
        });
      }
    }
  }
}
function p_display_bfd_configuration_all(b, model) {
  if (/bfd\s+all-interfaces\s+enable/i.test(b)) model.protocols.bfd.config.all_interfaces = true;
  if (/mpls-passive/i.test(b)) model.protocols.bfd.config.mpls_passive = true;
  const reflMatch = b.match(/reflector\s+discriminator\s+([0-9.]+)/i);
  if (reflMatch && reflMatch[1]) model.protocols.bfd.reflector.discriminator = reflMatch[1];
}

function p_display_ospf_peer_brief(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (!t || /^Area\s+Id|^----|^Router\s+ID|^\(M\)|Total/i.test(t)) continue;
    const m = t.match(/^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/);
    if (m) {
      model.protocols.ospf.neighbors.push({
        area: m[1],
        interface: m[2],
        neighbor_id: m[3].replace(/\(M\)/g, ""),
        state: m[4].replace(/\(M\)/g, "")
      });
    }
  }
}
function p_display_ospf_brief(b, model) {
  const ridMatch = b.match(/Router\s*ID\s*[: ]\s*([0-9.]+)/i);
  if (ridMatch && ridMatch[1]) model.protocols.ospf.router_ids.default = ridMatch[1];
}

function p_display_segment_routing(b, model) {
  const srgbMatch = b.match(/SRGB\s*:\s*(\d+)-(\d+)/i);
  if (srgbMatch) model.protocols.mpls.sr.srgb = { start: toInt(srgbMatch[1]), end: toInt(srgbMatch[2]) };
  const srlbMatch = b.match(/SRLB\s*:\s*(\d+)-(\d+)/i);
  if (srlbMatch) model.protocols.mpls.sr.srlb = { start: toInt(srlbMatch[1]), end: toInt(srlbMatch[2]) };
}
function p_display_mpls_lsp_statistics(b, model) {
  const srbeMatch = b.match(/srbe-lsp\s*[: ]\s*(\d+)/i) || b.match(/SR\s*BE.*?(\d+)/i);
  if (srbeMatch) model.protocols.mpls.sr.lsp_stats.srbe = toInt(srbeMatch[1]);
}
function p_display_tunnel_info_statistics(b, model) {
  const srbeMatch = b.match(/srbe-lsp\s+(\d+)/i);
  if (srbeMatch) model.protocols.mpls.sr.lsp_stats.srbe = toInt(srbeMatch[1]);
}

function p_display_bgp_peer(b, model) {
  for (const ln of lines(b)) {
    const m = ln.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)/);
    if (m) model.protocols.bgp.neighbors.push({ neighbor: m[1], as: toInt(m[2]), state: m[3] });
  }
}
function p_display_bgp_vpnv4_peer(b, model) {
  for (const ln of lines(b)) {
    const m = ln.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)/);
    if (m) model.protocols.bgp.vpnv4.push({ neighbor: m[1], as: toInt(m[2]), state: m[3] });
  }
}
function p_display_bgp_evpn_peer(b, model) {
    for (const ln of lines(b)) {
        const m = ln.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)/); // IP, AS, State, Uptime, Routes
        if (m) {
            model.protocols.bgp.evpn_peers.push({
                neighbor: m[1],
                as: toInt(m[2]),
                state: m[3],
                uptime: m[4],
                routes: toInt(m[5])
            });
        }
    }
}

function p_display_vpn_instance(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (!t || /^\*+/.test(t) || /^Name|^-----/.test(t)) continue;
    const m = t.match(/^([A-Za-z0-9\-_]+)\s+(\S+)/);
    if (m) {
      const name = m[1], af = [m[2]].filter(Boolean);
      const idx = model.protocols.vrfs.findIndex(v => v.name === name);
      if (idx >= 0) {
        const merged = model.protocols.vrfs[idx];
        const set = new Set([...(merged.af || []), ...af]);
        model.protocols.vrfs[idx] = { ...merged, af: [...set] };
      } else {
        model.protocols.vrfs.push({ name, af, router_id: null });
      }
    }
  }
}
function p_display_ip_routing_table_statistics(b, model) {
  const vrfMatch = (b.match(/VPN-Instance\s*:\s*([^\n\r]+)/i) || [])[1];
  const totalMatch = b.match(/Total\s+(\d+)/i);
  const sumMatch = b.match(/Summary\s+Prefixes\s*[: ]\s*(\d+)/i);
  const vrf = vrfMatch ? vrfMatch.trim() : null;
  
  const summary = {
      vrf: vrf,
      total_routes: totalMatch ? toInt(totalMatch[1]) : null,
      summary_prefixes: []
  };

  // New parser for multi-line prefix summary
  const protoLines = b.split('\nProto')[1]; // Get the table part
  if (protoLines) {
      for (const ln of lines(protoLines)) {
          const m = ln.match(/^\s*([A-Z-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/i);
          if (m) {
              summary.summary_prefixes.push({
                  proto: m[1],
                  total: toInt(m[2]),
                  active: toInt(m[3]),
                  added: toInt(m[4]),
                  deleted: toInt(m[5]),
                  freed: toInt(m[6])
              });
          }
      }
  } else if (sumMatch) {
      summary.summary_prefixes = toInt(sumMatch[1]); // Fallback for old format
  }
  
  if (summary.total_routes !== null || summary.summary_prefixes.length > 0)
    model.routing.table_summary.push(summary);
}

// ---------- Route map ----------
const ROUTES = [
  // identity/software/time/patch/ntp
  [/^dis(?:play)?\s+version/i, p_display_version],
  [/^dis(?:play)?\s+router\s+id\s+vpn-instance/i, p_display_router_id_vrf],
  [/^dis(?:play)?\s+router\s+id/i, p_display_router_id],
  [/^dis(?:play)?\s+mpls\s+lsr-id/i, p_display_mpls_lsr_id],
  [/^dis(?:play)?\s+clock/i, p_display_clock],
  [/^dis(?:play)?\s+patch-info(?:rmation)?/i, p_display_patch_information],
  [/^dis(?:play)?\s+startup/i, p_display_startup],
  [/^dis(?:play)?\s+ntp.*status/i, p_display_ntp_status],
  [/^dis(?:play)?\s+ntp.*unicast.*server/i, p_display_ntp_unicast],

  // resources
  [/^dis(?:play)?\s+cpu-usage/i, p_display_cpu_usage],
  [/^dis(?:play)?\s+health\s+verbose/i, p_display_health_verbose],
  [/^dir\s+cfcard::/i, p_dir_cfcard],
  [/^dis(?:play)?\s+device\s+\d+\b/i, p_display_power_any],
  [/^dis(?:play)?\s+power(\b|$)/i, p_display_power_any],
  [/^dis(?:play)?\s+temperature/i, p_display_temperature],
  [/^dis(?:play)?\s+fan/i, p_display_fan],
  [/^dis(?:play)?\s+alarm\s+active\s+verbose/i, p_display_alarm_all],
  [/^dis(?:play)?\s+alarm(\s|$)/i, p_display_alarm_all],

  // hardware / optics
  [/^dis(?:play)?\s+device\s+pic-status/i, p_display_device_pic_status],
  [/^dis(?:play)?\s+device(\s|$)/i, p_display_device],
  [/^dis(?:play)?\s+elabel/i, p_display_elabel],
  [/^dis(?:play)?\s+optical-module\s+(verbose|brief)/i, p_display_optical_module_any],

  // interfaces
  [/^dis(?:play)?\s+interface\s+ethernet\s+brief/i, p_display_interface_ethernet_brief],
  [/^dis(?:play)?\s+int(?:erface)?\s+brief/i, p_display_interface_brief],
  [/^dis(?:play)?\s+ip\s+int(?:erface)?/i, p_display_ip_interface],
  [/^dis(?:play)?\s+cur(?:rent-configuration)?/i, p_display_current_configuration], // Must be after specific 'dis'

  // protocols
  [/^dis(?:play)?\s+arp\s+all/i, p_display_arp_all],
  [/^dis(?:play)?\s+arp\s+statistics/i, p_display_arp_statistics],
  [/^dis(?:play)?\s+mac-address\s+(dynamic|summary)/i, p_display_mac_address_any],
  [/^dis(?:play)?\s+vlan(\s|$)/i, p_display_vlan],
  [/^dis(?:play)?\s+vxlan\s+vni\s+all/i, p_display_vxlan_vni_all],
  [/^dis(?:play)?\s+evpn\s+vpn-instance/i, p_display_evpn_vpn_instance],
  [/^dis(?:play)?\s+eth-trunk/i, p_display_eth_trunk],
  [/^dis(?:play)?\s+e-trunk/i, p_display_e_trunk],
  [/^dis(?:play)?\s+lacp\s+peer/i, p_display_lacp_peer],
  [/^dis(?:play)?\s+bfd\s+session/i, p_display_bfd_session_all],
  [/^dis(?:play)?\s+bfd\s+configuration/i, p_display_bfd_configuration_all],
  [/^dis(?:play)?\s+ospf\s+peer\s+brief/i, p_display_ospf_peer_brief],
  [/^dis(?:play)?\s+ospf\s+brief/i, p_display_ospf_brief],
  [/^dis(?:play)?\s+segment-routing/i, p_display_segment_routing],
  [/^dis(?:play)?\s+mpls\s+lsp\s+statistics/i, p_display_mpls_lsp_statistics],
  [/^dis(?:play)?\s+tunnel-info\s+statistics/i, p_display_tunnel_info_statistics],
  [/^dis(?:play)?\s+bgp\s+peer/i, p_display_bgp_peer],
  [/^dis(?:play)?\s+bgp\s+vpnv4.*peer/i, p_display_bgp_vpnv4_peer],
  [/^dis(?:play)?\s+bgp\s+evpn\s+peer/i, p_display_bgp_evpn_peer],
  [/^dis(?:play)?\s+vpn-instance/i, p_display_vpn_instance],
  [/^dis(?:play)?\s+ip\s+routing-table\s+(all-vpn-instance\s+)?statistics/i, p_display_ip_routing_table_statistics],

  // licenses
  [/^dis(?:play)?\s+license\s+esn/i, p_display_license_esn],
  [/^dis(?:play)?\s+license\s+verbose/i, p_display_license_verbose],
];

// ---------- Parse One File ----------
function parseFile(inFile) {
  const raw = fs.readFileSync(inFile, "utf8");
  const model = newModel();
  ensureInterface._map = new Map(); // Clear interface map for each file

  // hostname
  const hnMatch = raw.match(/^<([^>]+)>/m);
  if (hnMatch && hnMatch[1]) model.identity.hostname = hnMatch[1];
  
  let hasConfigData = false;
  
  // --- PASS 1: RAW CONFIG PARSING ---
  // Check if it looks like a raw config file (log_example1.log)
  // or an interactive log that includes 'dis cur' (log_example2.txt)
  if (RAW_CONFIG_REGEX.test(raw) || /dis(?:play)?\s+cur(?:rent-configuration)?/i.test(raw)) {
      console.log(`File ${inFile} has config data, running config parser...`);
      hasConfigData = true;
      try {
          // If it's *only* a raw config, use the full text.
          // If it's an interactive log, find just the 'dis cur' block.
          let configBlock = raw;
          if (!RAW_CONFIG_REGEX.test(raw)) { // It's not a raw config, find 'dis cur'
              const blocks = splitBlocks(raw);
              for (const block of blocks) {
                  const cmd = detectCommand(block);
                  if (/^dis(?:play)?\s+cur(?:rent-configuration)?/i.test(cmd)) {
                      configBlock = stripCommandFromBlock(block);
                      break; // Found it
                  }
              }
          }
          p_display_current_configuration(configBlock, model);
      } catch (e) {
          console.error(`Error in config parser: ${e.message}`);
          model.raw_sections['config_parser_error'] = [{ error: e.message, raw: e.stack }];
      }
  }

  // --- PASS 2: BLOCK-BY-BLOCK PARSING ---
  // This handles all `display` commands (log_example2.txt, CommonCollectResult.txt)
  const blk = splitBlocks(raw);
  for (const block of blk) {
    const cmd = detectCommand(block);
    let handled = false;
    
    // Don't re-run 'dis cur' if we already did
    if (hasConfigData && /^dis(?:play)?\s+cur(?:rent-configuration)?/i.test(cmd)) {
        continue;
    }
    
    const cleanBlock = stripCommandFromBlock(block); // Clean prompt line

    for (const [rx, fn] of ROUTES) {
      if (rx.test(cmd)) {
        try {
          fn(cleanBlock, model); // Pass the cleaned block
        } catch (e) {
          console.error(`Error in parser for cmd '${cmd}': ${e.message}`);
          const key = normalizeKey(cmd);
          (model.raw_sections[key] ||= []).push({ error: e.message, raw: cleanTailPrompt(cleanBlock) });
        }
        handled = true;
        break; // First match wins
      }
    }
    if (!handled && cmd !== 'unknown') {
      const key = normalizeKey(cmd);
      (model.raw_sections[key] ||= []).push({ raw: cleanTailPrompt(cleanBlock) });
    }
  }

  // --- CLEANUP ---
  model.identity.ssh_users = uniqBy(model.identity.ssh_users, 'name');
  model.ntp.servers = uniqBy(model.ntp.servers, 'ip');
  model.interfaces = uniqBy(model.interfaces, 'name');
  model.protocols.vrfs = uniqBy(model.protocols.vrfs, 'name');
  model.alarms = uniqBy(model.alarms, 'description');
  model.protocols.bgp.config_peers = uniqBy(model.protocols.bgp.config_peers, 'peer_ip');
  model.protocols.isis.processes = uniqBy(model.protocols.isis.processes, 'id');

  // console summary
  console.log("\n✅ Parsed:", path.basename(inFile));
  console.log("→ Output :", outPathFor(inFile));
  console.log("— Hostname      :", model.identity.hostname || model.identity.sysname || "N/A");
  console.log("— Model         :", model.identity.model || "N/A");
  console.log("— Version       :", model.software.version || "N/A");
  console.log("— Uptime        :", model.software.uptime || "N/A");
  console.log("— Serial (ESN)  :", model.identity.serial || "N/A");
  console.log("— Router ID Pub :", model.identity.router_id_public || "N/A");
  console.log("— LSR ID        :", model.identity.lsr_id || "N/A");
  console.log("— TZ / Now      :", model.identity.timezone || "N/A", "/", model.identity.current_time || "N/A");
  console.log("— NTP servers   :", (model.ntp.servers || []).map(s=>s.ip).join(", ") || "N/A");
  console.log("— CPU samples   :", model.resources.cpu.length);
  console.log("— Mem samples   :", model.resources.memory.length);
  console.log("— Disk samples  :", model.resources.disk.length);
  console.log("— PSU entries   :", model.resources.power.length);
  console.log("— Temps / Fans  :", model.resources.temperature.length, "/", model.resources.fan.length);
  console.log("— Cards / PICs  :", model.hardware.cards.length, "/", model.hardware.pics.length);
  console.log("— E-Labels / SFP:", model.hardware.elabels.length, "/", model.hardware.sfp.length);
  console.log("— Interfaces    :", model.interfaces.length);
  console.log("— ARP / MAC     :", model.protocols.arp.length, "/", model.protocols.mac.length);
  console.log("— VLANs         :", model.protocols.vlans.length);
  console.log("— Eth/E-Trunks  :", model.protocols.trunks.eth_trunks.length, "/", model.protocols.trunks.e_trunks.length);
  console.log("— BFD / OSPF    :", model.protocols.bfd.sessions.length, "/", model.protocols.ospf.neighbors.length);
  console.log("— ISIS Procs    :", model.protocols.isis.processes.length);
  console.log("— BGP Peers     :", model.protocols.bgp.neighbors.length, `(EVPN: ${model.protocols.bgp.evpn_peers.length} )`);
  console.log("— BGP Config    :", model.protocols.bgp.config_peers.length);
  console.log("— SRBE count    :", model.protocols.mpls.sr.lsp_stats.srbe || 0);
  console.log("— EVPN Inst/VNI :", model.protocols.evpn.instances.length, "/", model.protocols.vxlan.vnis.length);
  console.log("— Route summary :", model.routing.table_summary.length);
  console.log("— Static routes :", model.routing.static.length);
  console.log("— Alarms        :", model.alarms.length);

  return model;
}

// Export parseFile so the analyzer can be required programmatically
module.exports = parseFile;
module.exports.parseFile = parseFile;

/**
 * Analyzes a single file and writes the JSON output.
 * @param {string} filePath - Path to the log file.
 * @returns {object} - An object { outputPath, deviceName }
 */
function analyzeFile(filePath) {
  const fullPath = path.resolve(filePath);
  if (!fs.existsSync(fullPath)) throw new Error(`File not found: ${fullPath}`);
  
  ensureOutDir();
  const model = parseFile(fullPath);
  const outFile = outPathFor(fullPath);
  
  fs.writeFileSync(outFile, JSON.stringify(model, null, 2), "utf8");
  
  // CRITICAL FIX (v13): Return object with deviceName
  const deviceName = model.identity.sysname || model.identity.hostname;
  return { outputPath: outFile, deviceName: deviceName || null }; 
}

function findLogFilesRecursively(currentDir) {
    let logFiles = [];
    const items = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const item of items) {
        const fullPath = path.join(currentDir, item.name);

        if (item.isDirectory()) {
            logFiles = logFiles.concat(findLogFilesRecursively(fullPath));
        } else if (item.isFile() && (item.name.toLowerCase().endsWith(".txt") || item.name.toLowerCase().endsWith(".log"))) {
            logFiles.push(fullPath);
        }
    }
    return logFiles;
}

/**
 * Analyzes all .txt/.log files in a directory.
 * @param {string} dirPath - Path to the directory.
 * @returns {Array<object>} - An array of { outputPath, deviceName } objects.
 */
function analyzeDirectory(dirPath) {
  const dir = path.resolve(dirPath);
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    throw new Error(`Not a directory: ${dir}`);
  }
  const files = findLogFilesRecursively(dir);
  if (!files.length) throw new Error(`No .txt or .log files found in: ${dir}`);

  ensureOutDir();
  const results = [];
  for (const f of files) {
    try {
      const analysisResult = analyzeFile(f); // This now returns the object
      results.push(analysisResult);
    } catch (e) {
        console.error(`Failed to parse file ${f}: ${e.message}`);
    }
  }
  
  // CRITICAL FIX (v13): Return the array of result objects
  return results;
}

// export for external use
module.exports = {
  parseFile,
  analyzeFile,
  analyzeDirectory
};

// Run as CLI only when invoked directly
if (require.main === module) {
  try {
    if (DIR_MODE) {
      console.log("📂 Scanning directory:", DIR_PATH);
      analyzeDirectory(DIR_PATH);
    } else {
      const file = FILE_PATH || DEFAULT_FILE;
      console.log("🔍 Parsing file:", file);
      analyzeFile(file);
    }
  } catch (err) {
    console.error("❌", err.stack || err.message);
    process.exit(1);
  }
}