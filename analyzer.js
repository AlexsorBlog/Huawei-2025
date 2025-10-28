/**
 * analyzer.js — Huawei VRP Universal Log Analyzer (v3)
 * ----------------------------------------------------
 * - One-file Node.js parser for VRP devices (NE/CE/AR/S).
 * - Builds a fully structured JSON model (identity, metrics, hardware,
 *   interfaces, protocols, routing, alarms, licenses).
 * - Efficient: no external deps; avoids huge string copies; suitable for laptops.
 *
 * Usage:
 *   node analyzer.js                      # parse ./CommonCollectResult.txt
 *   node analyzer.js --file ./foo.txt     # parse specific file
 *   node analyzer.js --dir  ./logs        # parse all *.txt in a folder
 *
 * Output:
 *   ./output/parsed_<filename>.json
 */

const fs = require("fs");
const path = require("path");

// ---------- Settings ----------
const DEFAULT_FILE = path.join(process.cwd(), "CommonCollectResult.txt");
const MARKER = "=========######HUAWEI#####=========";
const OUT_DIR = path.join(process.cwd(), "output");

// ---------- CLI ----------
const getArg = (flag) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : null;
};
const DIR_PATH = getArg("--dir");
const FILE_PATH = getArg("--file");
const DIR_MODE = !!DIR_PATH;

// ---------- Utils ----------
const ensureOutDir = () => {
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });
};
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
const uniq = (arr) => [...new Set(arr || [])];
const lower = (s) => String(s || "").toLowerCase();
const normalizeKey = (s) => String(s || "").replace(/[^a-z0-9]+/gi, "_").toLowerCase();
const lines = (block) => block.split(/\r?\n/);

// ---------- Block splitting / command detection ----------
function splitBlocks(raw) {
  if (raw.includes(MARKER)) {
    return raw.split(MARKER).map((s) => s.trim()).filter(Boolean);
  }
  // fallback heuristic if no markers
  return raw.split(/\n(?=<[^>]+>)|(?=^display\s+)/im).map((s) => s.trim()).filter(Boolean);
}
function detectCommand(block) {
  for (const l of lines(block)) {
    const t = l.trim();
    if (!t) continue;
    if (/^<.*>$/.test(t) || /^\[~?.*]$/.test(t)) continue;
    if (
      /^(display|interface|controller|return|system|diagnose|bgp|ospf|isis|mpls|segment-routing|ip\s+route|ipsec|vxlan|evpn|vlan|eth-trunk|lacp|bfd|vrrp|lldp|vrf|vpn-instance|clock|ntp|patch|dir\s+cfcard)/i.test(
        t
      )
    )
      return t;
    if (/display/i.test(t)) return t;
    return t;
  }
  return "unknown";
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
      router_id_public: null,    // LoopBack0/public
      router_ids: {},            // { vrfName: routerId }
      timezone: null,            // full TZ string (e.g., "Europe/Kiev add 02:00:00 DST")
      current_time: null,        // parsed from display clock
      patch_status: null,        // "none" or exact phrase ("Info: No patch exists.")
      config_saved: null,        // saved-configuration path/time if present
      ssh_users: [],
      mac_addrs: { chassis: null, base: null }
    },
    software: { version: null, uptime: null },

    ntp: { state: null, stratum: null, servers: [] },

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
      trunks: [],      // [{ type:'Eth-Trunk|E-Trunk|LACP',id,mode,state,members:[] }]
      lldp: { enabled: null, neighbors: [] }, // neighbors optional
      vrrp: { enabled: null, groups: [] },
      bfd: { sessions: [], config: {}, reflector: {} },
      ospf: { neighbors: [], areas: [], router_ids: {} },
      isis: { neighbors: [], areas: [] },
      bgp: { neighbors: [], vpnv4: [], vpnv6: [] },
      vrfs: [],        // [{ name, af:['ipv4','ipv6'], router_id }]
      mpls: { ldp: {}, te: {}, sr: { srgb: null, srlb: null, lsp_stats: { srbe: null } } },
      evpn: []         // [{ evi,vni,mac,ip,next_hop }]
    },

    routing: {
      table_summary: [], // [{ vrf,total_routes,summary_prefixes }]
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
  const ver = txt.match(/VRP.*?Version\s*([^\n\r]+)/i) || txt.match(/Version\s*([^\n\r]+)/i);
  if (ver) {
    const v = ver[1].trim();
    const pure = v.replace(/\(.*?\)\s*$/, "").trim();
    model.software.version = pure || v;
    model.identity.version = model.software.version;
  }
  const up = txt.match(/uptime\s+is\s*([^\n\r]+)/i);
  if (up) model.software.uptime = up[1].trim();

  // try to extract model independently & cleanly
  const mod =
    txt.match(/NetEngine\s+([^\n\r]+?)(?:\s+uptime|\)|$)/i) ||
    txt.match(/Device\s+Type\s*[:]\s*([^\n\r]+)/i);
  if (mod) model.identity.model = ("NetEngine " + mod[1].trim()).replace(/NetEngine NetEngine/i, "NetEngine").replace(/V800R0.*$/i, "").trim();
}

function p_display_router_id(b, model) {
  // "RouterID: 172.x.x.x"
  const m = b.match(/RouterID\s*:\s*([0-9.]+)/i);
  if (m) model.identity.router_id_public = m[1];
}

function p_display_router_id_vrf(b, model) {
  // "display router id vpn-instance NAME" -> "RouterID: x.x.x.x"
  const name = (b.match(/vpn-instance\s+([^\n\r]+)/i) || [])[1];
  const rid = (b.match(/RouterID\s*:\s*([0-9.]+)/i) || [])[1];
  if (name && rid) {
    model.identity.router_ids[name.trim()] = rid.trim();
    // also ensure it exists in protocols.vrfs
    const idx = model.protocols.vrfs.findIndex(v => v.name === name.trim());
    if (idx >= 0) model.protocols.vrfs[idx].router_id = rid.trim();
    else model.protocols.vrfs.push({ name: name.trim(), af: null, router_id: rid.trim() });
  }
}

function p_display_clock(b, model) {
  const head = lines(b)[0] || "";
  if (/\d{4}-\d{2}-\d{2}/.test(head)) model.identity.current_time = head.trim();
  const tz =
    b.match(/Time\s*Zone\s*\(([^)]+)\)/i) ||
    b.match(/Time\s*Zone\s*:\s*([^\n\r]+)/i) ||
    b.match(/time\s*zone\s*:\s*([^\n\r]+)/i);
  if (tz) model.identity.timezone = tz[1].trim();
}

function p_display_patch_information(b, model) {
  if (/No\s+patch\s+exists/i.test(b)) {
    model.identity.patch_status = "Info: No patch exists.";
    return;
  }
  const st =
    b.match(/current state is\s*[: ]\s*([^\n\r]+)/i) ||
    b.match(/patch.*state\s*[:]\s*([^\n\r]+)/i);
  if (st) model.identity.patch_status = st[1].trim();
}

function p_display_startup(b, model) {
  const cfg = (b.match(/Startup saved-configuration file\s*:\s*([^\n\r]+)/i) || [])[1];
  if (cfg) model.identity.config_saved = cfg.trim();
}

function p_display_ntp_status(b, model) {
  const state = b.match(/clock status\s*:\s*(\S+)/i);
  if (state) model.ntp.state = state[1];
  const stratum = b.match(/clock stratum\s*:\s*(\d+)/i);
  if (stratum) model.ntp.stratum = toInt(stratum[1]);
  // sometimes shows current servers too; capture any IPs
  const ips = [...b.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)].map(m => m[1]);
  if (ips.length) model.ntp.servers = uniq([...(model.ntp.servers || []), ...ips]);
}
function p_display_ntp_unicast(b, model) {
  const ips = [...b.matchAll(/ntp\s+unicast-?server\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+preference)?/gi)].map(m => m[1]);
  if (ips.length) model.ntp.servers = uniq([...(model.ntp.servers || []), ...ips]);
}

// licenses
function p_display_license_esn(b, model) {
  const esn = (b.match(/ESN\s*:\s*([^\s\r\n]+)/i) || [])[1];
  if (esn) model.identity.serial = esn.trim();
}
function p_display_license_verbose(b, model) {
  const txt = cleanTailPrompt(b);
  const parts = txt.split(/\n(?=Sale\s+name)|(?=^Sale\s+name)/im).filter(p => /Sale\s+name/i.test(p));
  for (const p of parts) {
    const sale = p.match(/Sale\s+name\s*:\s*(.*)/i)?.[1] || "";
    const item = p.match(/Item\s+name\s*:\s*(.*)/i)?.[1] || "";
    const control = p.match(/Control\s+value\s*:\s*(.*)/i)?.[1] || "";
    const used = p.match(/Used\s+value\s*:\s*(.*)/i)?.[1] || "";
    const desc = p.match(/Description\s*:\s*([\s\S]*?)(?:\n\n|$)/i)?.[1] || "";
    model.licenses.push({
      sale_name: sale.trim(),
      item_name: item.trim(),
      control_value: control.trim(),
      used_value: used.trim(),
      description: desc.replace(/\s+/g, " ").trim()
    });
  }
}

// ---------- Resources (CPU/memory/disk/power/temp/fan/alarms) ----------
function p_display_cpu_usage(b, model) {
  const entry = {};
  const sys = b.match(/System cpu use rate is\s*:?\s*(\d+)%/i);
  if (sys) entry.avg = toInt(sys[1]);
  const avg = b.match(/five seconds\s*:\s*(\d+)%/i) || b.match(/5\s*sec.*?(\d+)%/i);
  if (avg && entry.avg == null) entry.avg = toInt(avg[1]);
  const max = b.match(/max.*?(\d+)%/i);
  if (max) entry.max = toInt(max[1]);
  const ts = b.match(/time\s*[: ]\s*([0-9\-: ]{10,})/i);
  if (ts) entry.ts = ts[1].trim();
  // per-service
  const per = [];
  for (const m of b.matchAll(/^\s*([A-Za-z0-9_\-\/]+)\s+(\d+)%/gm)) {
    if (!/System|five|max|CPU/i.test(m[1])) per.push({ name: m[1], pct: toInt(m[2]) });
  }
  if (per.length) entry.per_service = per;
  if (Object.keys(entry).length) model.resources.cpu.push(entry);
}

function p_display_health_verbose(b, model) {
  // e.g. Used/Total (3935MB/14798MB), Physical Free/Total (10862MB/14798MB), Cache (2573MB)
  const usedTotal = b.match(/Used\/Total\s*\(\s*([0-9.]+)\s*MB\s*\/\s*([0-9.]+)\s*MB\s*\)/i);
  const phys = b.match(/Physical\s+Free\/Total\s*\(\s*([0-9.]+)\s*MB\s*\/\s*([0-9.]+)\s*MB\s*\)/i);
  const cache = b.match(/Cache\s*\(\s*([0-9.]+)\s*MB\s*\)/i);
  const usagePct = b.match(/Memory\s+Usage\s*\(\%\)\s*:\s*(\d+)/i);
  if (usedTotal || phys || cache) {
    model.resources.memory.push({
      used_mb: usedTotal ? toFloat(usedTotal[1]) : null,
      total_mb: usedTotal ? toFloat(usedTotal[2]) : null,
      free_mb: phys ? toFloat(phys[1]) : null,
      phys_total_mb: phys ? toFloat(phys[2]) : null,
      cache_mb: cache ? toFloat(cache[1]) : null,
      usage_pct: usagePct ? toInt(usagePct[1]) : null
    });
  }
}

function p_dir_cfcard(b, model) {
  // "Total: 13,238,234 KB, Free: 9,194,587 KB"
  const m = b.match(/Total:\s*([0-9,]+)\s*KB,\s*Free:\s*([0-9,]+)\s*KB/i);
  if (m) {
    const total = toInt(m[1]);
    const free = toInt(m[2]);
    model.resources.disk.push({ source: "cfcard", total_kb: total, free_kb: free, used_kb: total - free });
  }
}

function p_display_power_any(b, model) {
  // Works for "display device 6/7" or "display power"
  const slot =
    b.match(/(?:Device|Power|Slot)\s*[: ]\s*(\d+)/i)?.[1] ||
    b.match(/Power\s+Board\s+(\d+)/i)?.[1] ||
    null;
  const volt = b.match(/Input\s*Voltage\s*:\s*([0-9.]+)\s*V/i) || b.match(/InputVoltage\s*:\s*([0-9.]+)/i);
  const curr = b.match(/Input\s*Current\s*:\s*([0-9.]+)\s*A/i) || b.match(/InputCurrent\s*:\s*([0-9.]+)/i);
  const watt = b.match(/Total\s*Power\s*:\s*([0-9.]+)\s*W/i) || b.match(/TotalPower\s*:\s*([0-9.]+)/i);
  const entry = {
    slot: slot ? slot.trim() : null,
    input_voltage_v: volt ? toFloat(volt[1]) : null,
    input_current_a: curr ? toFloat(curr[1]) : null,
    total_power_w: watt ? toFloat(watt[1]) : null
  };
  if (Object.values(entry).some(v => v !== null)) model.resources.power.push(entry);
}

function p_display_temperature(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (!t) continue;
    if (/^Base-Board|^PCB|^\-+|^Sensor|^Location|^display\s+temperature/i.test(t)) continue;
    const tokens = t.split(/\s+/);
    const last = tokens[tokens.length - 1];
    if (/^-?\d+$/.test(last) && tokens[0] && !/^[-]+$/.test(tokens[0])) {
      const status = (t.match(/(NORMAL|MINOR|MAJOR|FATAL)/i) || [])[1];
      model.resources.temperature.push({
        pcb: tokens[0],
        slot: /^\d+$/.test(tokens[1]) ? tokens[1] : null,
        status: status ? status.toUpperCase() : null,
        temp_c: toInt(last)
      });
    }
  }
}

function p_display_fan(b, model) {
  const status = (b.match(/Status\s*:\s*([A-Za-z0-9_]+)/i) || [])[1] || null;
  const speeds = [...b.matchAll(/\[(\d+)\]\s*(\d+)%/g)].map(m => ({ id: toInt(m[1]), speed_percent: toInt(m[2]) }));
  if (status || speeds.length) model.resources.fan.push({ status, speeds });
}

function p_display_alarm_all(b, model) {
  // Preserve full descriptions; merge wrapped lines
  const txt = cleanTailPrompt(b);
  // try table lines first
  for (const ln of lines(txt)) {
    const m = ln.match(/^\s*(\d+)\s+(\w+)\s+(\d{4}-\d{2}-\d{2})\s+(\S+)\s+(.*)$/);
    if (m) {
      model.alarms.push({
        sequence: toInt(m[1]),
        level: m[2],
        date: m[3],
        time: m[4],
        description: m[5].trim()
      });
    }
  }
  // fallback: verbose chunks
  const chunks = txt.split(/\n\s*\n/).filter(Boolean);
  for (const c of chunks) {
    if (/Sequence\s*:/i.test(c)) {
      model.alarms.push({
        sequence: toInt(c.match(/Sequence\s*:\s*(\d+)/i)?.[1]),
        alarm_id: c.match(/AlarmId\s*:\s*(\S+)/i)?.[1] || null,
        name: c.match(/AlarmName\s*:\s*(\S+)/i)?.[1] || null,
        severity: c.match(/Severity\s*:\s*(\S+)/i)?.[1] || null,
        state: c.match(/State\s*:\s*(\S+)/i)?.[1] || null,
        start_time: c.match(/StartTime\s*:\s*([^\n\r]+)/i)?.[1] || null,
        description: (c.match(/Description\s*:\s*([\s\S]*)/i)?.[1] || "").replace(/\s+/g, " ").trim()
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
  // parse many elabel blocks: board, pic, fan, power, optics
  const scope =
    (b.match(/Elabel\s+of\s+([^\n\r]+)/i) || [])[1] ||
    (b.match(/Device\s*:\s*([^\n\r]+)/i) || [])[1] ||
    (b.match(/Board\s*:\s*([^\n\r]+)/i) || [])[1] ||
    "unknown";
  const slot = (b.match(/Slot\s*[: ]\s*(\d+)/i) || [])[1] || null;
  const mfr = (b.match(/(?:Manufacturer|VendorName)\s*[: ]\s*([^\n\r]+)/i) || [])[1] || null;
  const pn =
    (b.match(/Part\s*Number\s*[: ]\s*([^\n\r]+)/i) || [])[1] ||
    (b.match(/Item\s*[: ]\s*([^\n\r]+)/i) || [])[1] || null;
  const bc = (b.match(/BarCode\s*[: ]\s*([^\n\r]+)/i) || [])[1] || null;
  const desc = (b.match(/Description\s*[: ]\s*([^\n\r]+)/i) || [])[1] || null;
  const mdl = (b.match(/Model\s*[: ]\s*([^\n\r]+)/i) || [])[1] || null;

  model.hardware.elabels.push({
    scope: scope.trim(),
    slot: slot ? toInt(slot) : null,
    manufacturer: mfr ? mfr.trim() : null,
    part_number: pn ? pn.trim() : null,
    barcode: bc ? bc.trim() : null,
    item: pn ? pn.trim() : null,
    description: desc ? desc.trim() : null,
    model: mdl ? mdl.trim() : null
  });

  // sometimes MACs are here
  const chassis = (b.match(/Chassis\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  const base = (b.match(/Base\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  if (chassis) model.identity.mac_addrs.chassis = chassis.toLowerCase();
  if (base) model.identity.mac_addrs.base = base.toLowerCase();
}

function p_display_optical_module_any(b, model) {
  // robust lines capturing rx/tx/wavelength/vendor pn
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (!t) continue;
    // common pattern:
    // PORT STATUS TYPE Rx(dBm) Tx(dBm) WL(nm) VendorPN
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
    // secondary: look for "... nm" lines
    const wl = t.match(/(\d{4,5})\s*nm/i);
    if (wl) {
      const port = t.split(/\s+/)[0];
      model.hardware.sfp.push({ port, wavelength_nm: toInt(wl[1]) });
    }
  }
}

// ---------- Interfaces ----------
function p_display_interface_brief(b, model) {
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (/^(GigabitEthernet|X?GE|Eth|100GE|25GE|40GE|10GE|LoopBack|Ethernet|NULL)/i.test(t)) {
      const p = t.split(/\s{2,}/).map(s => s.trim()).filter(Boolean);
      if (p.length >= 3) {
        const itf = ensureInterface(model, p[0]);
        itf.status = p[1];
        itf.protocol = p[2];
        if (p[3]) itf.in_util = p[3];
        if (p[4]) itf.out_util = p[4];
      }
    }
  }
}
function p_display_interface_ethernet_brief(b, model) {
  // bandwidth/duplex lines
  for (const ln of lines(b)) {
    const t = ln.trim();
    const name = t.split(/\s+/)[0];
    const m = t.match(/\s(half|full)\s+(\d+)([MG])/i);
    if (name && m) {
      const itf = ensureInterface(model, name);
      itf.duplex = m[1].toUpperCase();
      const num = toInt(m[2]); const unit = m[3].toUpperCase();
      itf.bandwidth_mbps = unit === "G" ? num * 1000 : num;
    }
  }
}
function p_display_ip_interface(b, model) {
  const blk = cleanTailPrompt(b);
  for (const part of blk.split(/\n(?=Interface\s*:)/i)) {
    const name = (part.match(/Interface\s*:\s*(\S+)/i) || [])[1];
    if (!name) continue;
    const itf = ensureInterface(model, name);
    const ipv4 = part.match(/IP\s*Address\s*:\s*([0-9.]+)\s+([0-9.]+)/i);
    if (ipv4) { itf.ip = ipv4[1]; itf.mask = ipv4[2]; }
    const vpn = part.match(/VPN-Instance\s*:\s*([^\n\r]+)/i);
    if (vpn) itf.vpn_instance = vpn[1].trim();
  }
}
function p_display_current_configuration(b, model) {
  const txt = cleanTailPrompt(b);
  // sysname
  const sys = txt.match(/^\s*sysname\s+([^\s\r\n]+)/im);
  if (sys) model.identity.sysname = sys[1];

  // ssh users
  const users = [...txt.matchAll(/^\s*ssh\s+user\s+([^\s\r\n]+)/gim)].map(m => m[1]);
  if (users.length) model.identity.ssh_users = uniq([...(model.identity.ssh_users || []), ...users]);

  // VRFs (vpn-instance) and router-id inside block
  for (const m of txt.matchAll(/^\s*vpn-instance\s+([^\s\r\n]+)/gim)) {
    const name = m[1];
    const start = m.index || 0;
    const window = txt.slice(start, start + 1200);
    const rid = window.match(/router-id\s+([0-9.]+)/i)?.[1] || null;
    const af = [];
    if (/ipv4/i.test(window)) af.push("ipv4");
    if (/ipv6/i.test(window)) af.push("ipv6");
    const entry = { name, af: af.length ? af : null, router_id: rid };
    const idx = model.protocols.vrfs.findIndex(v => v.name === name);
    if (idx >= 0) model.protocols.vrfs[idx] = { ...model.protocols.vrfs[idx], ...entry };
    else model.protocols.vrfs.push(entry);
    if (rid) model.identity.router_ids[name] = rid;
  }

  // Router-ID public via LoopBack0
  const loBlk = txt.split(/\n(?=interface\s+LoopBack0\b)/i)[1];
  if (loBlk) {
    const loIP = loBlk.match(/ip\s+address\s+([0-9.]+)\s+[0-9.]+/i);
    if (loIP) model.identity.router_id_public = loIP[1];
  }

  // NTP servers configured
  const ntps = [...txt.matchAll(/^\s*ntp\s+unicast-?server\s+([0-9.]+)/gim)].map(m => m[1]);
  if (ntps.length) model.ntp.servers = uniq([...(model.ntp.servers || []), ...ntps]);

  // LLDP / VRRP flags (status)
  model.protocols.lldp.enabled = /^(?:\s*)lldp\s+enable/im.test(txt) ? true : (model.protocols.lldp.enabled ?? null);
  model.protocols.vrrp.enabled = /^(?:\s*)vrrp\b/im.test(txt) ? true : false;

  // Static routes
  for (const m of txt.matchAll(/^\s*ip\s+route-static\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)(?:\s+(\S+))?/gim)) {
    model.routing.static.push({ vrf: null, prefix: m[1], mask: m[2], next_hop: m[3], iface: m[4] || null });
  }

  // Interfaces: enrich description, IP, IPv6, VRF, bandwidth
  const ifaceBlocks = txt.split(/\n(?=interface\s+)/i).filter(s => /^interface\s+/i.test(s.trim()));
  for (const blk of ifaceBlocks) {
    const firstLine = blk.split(/\r?\n/)[0] || "";
    const name = firstLine.replace(/^interface\s+/i, "").trim();
    if (!name) continue;
    const itf = ensureInterface(model, name);
    const desc = blk.match(/^\s*description\s+(.+)$/im);
    if (desc) itf.description = desc[1].trim();
    const ipv4 = blk.match(/^\s*ip\s+address\s+([0-9.]+)\s+([0-9.]+)/im);
    if (ipv4) { itf.ip = ipv4[1]; itf.mask = ipv4[2]; }
    const ipv6 = blk.match(/^\s*ipv6\s+address\s+([0-9a-fA-F:\/]+)/im);
    if (ipv6) itf.ipv6 = ipv6[1];
    const vrf = blk.match(/^\s*vpn-instance\s+([^\s\r\n]+)/im);
    if (vrf) itf.vpn_instance = vrf[1];
    const bw = blk.match(/^\s*(speed|bandwidth)\s+(\d+)(G|M|K)?/im);
    if (bw) {
      let val = toInt(bw[2]); const unit = (bw[3] || "M").toUpperCase();
      itf.bandwidth_mbps = unit === "G" ? val * 1000 : unit === "K" ? Math.round(val / 1000) : val;
    }
  }

  // MPLS SRGB/SRLB config (segment-routing)
  const srgb = txt.match(/segment\-routing\s+global\-block\s+(\d+)\s+(\d+)/i);
  if (srgb) model.protocols.mpls.sr.srgb = { start: toInt(srgb[1]), end: toInt(srgb[2]) };
  const srlb = txt.match(/segment\-routing\s+local\-block\s+(\d+)\s+(\d+)/i);
  if (srlb) model.protocols.mpls.sr.srlb = { start: toInt(srlb[1]), end: toInt(srlb[2]) };
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
  const tot = b.match(/Total\s*[: ]\s*(\d+)/i);
  const dyn = b.match(/Dynamic\s*[: ]\s*(\d+)/i);
  if (tot || dyn) model.protocols.arp.push({ stats: { total: toInt(tot?.[1]), dynamic: toInt(dyn?.[1]) } });
}

function p_display_mac_address_any(b, model) {
  // dynamic table rows
  for (const ln of lines(b)) {
    const m = ln.match(/^\s*(\d+)\s+([0-9a-fA-F.\-:]{12,})\s+(\S+)/);
    if (m) model.protocols.mac.push({ vlan: toInt(m[1]), mac: m[2].toLowerCase(), interface: m[3], type: "dynamic" });
  }
  // chassis/base mac hints if appear here
  const chassis = (b.match(/Chassis\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  const base = (b.match(/Base\s+MAC\s*[: ]\s*([0-9a-f.\-:]+)/i) || [])[1];
  if (chassis) model.identity.mac_addrs.chassis = chassis.toLowerCase();
  if (base) model.identity.mac_addrs.base = base.toLowerCase();
}

function p_display_vlan(b, model) {
  const txt = cleanTailPrompt(b);
  const blocks = txt.split(/\n(?=VLAN\s+\d+)/i).filter(x => /VLAN\s+\d+/.test(x));
  for (const bl of blocks) {
    const id = bl.match(/VLAN\s+(\d+)/i);
    const name = bl.match(/Name\s*:\s*([^\n\r]+)/i);
    const type = bl.match(/Type\s*:\s*([^\n\r]+)/i);
    const members = [...bl.matchAll(/(?:GE|Eth|XGE|100GE|25GE|40GE|10GE)\S+/g)].map(m => m[0]);
    model.protocols.vlans.push({ id: id ? toInt(id[1]) : null, name: name ? name[1].trim() : null, type: type ? type[1].trim() : null, members: uniq(members) });
  }
}

function p_display_vxlan(b, model) {
  for (const m of b.matchAll(/VNI\s*[: ]\s*(\d+)/gi)) {
    model.protocols.vlans.push({ vxlan_vni: toInt(m[1]) });
  }
}

function p_display_eth_trunk(b, model) {
  const trunks = {};
  let current = null;
  for (const ln of lines(b)) {
    const t = ln.trim();
    const head = t.match(/^Eth-Trunk(\d+)\s+(\S+)/i);
    if (head) {
      current = head[1];
      trunks[current] = { type: "Eth-Trunk", id: current, state: head[2], members: [] };
      continue;
    }
    const mem = t.match(/Members?\s*:\s*(.+)$/i);
    if (mem && current) {
      const ids = mem[1].match(/(?:GE|Eth|100GE|25GE|40GE|10GE)\S+/g) || [];
      trunks[current].members = uniq(ids);
    }
  }
  model.protocols.trunks.push(...Object.values(trunks));
}

function p_display_lacp_peer(b, model) {
  for (const ln of lines(b)) {
    const m = ln.match(/^Eth-Trunk(\d+)\s+(\S+)\s+Actor:\s*(\S+).*?Partner:\s*(\S+)/i);
    if (m) model.protocols.trunks.push({ type: "LACP", id: m[1], mode: m[2], actor: m[3], partner: m[4] });
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
  const refl = b.match(/reflector\s+discriminator\s+([0-9.]+)/i);
  if (refl) model.protocols.bfd.reflector.discriminator = refl[1];
}

function p_display_ospf_peer_brief(b, model) {
  // expect clean columns: AreaId Interface NeighborId State ...
  for (const ln of lines(b)) {
    const t = ln.trim();
    if (!t || /^Area\s+Id|^----|^Router\s+ID/i.test(t)) continue;
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
  const rid = b.match(/Router\s*ID\s*[: ]\s*([0-9.]+)/i);
  if (rid) model.protocols.ospf.router_ids.default = rid[1];
}

function p_display_segment_routing(b, model) {
  const srgb = b.match(/SRGB\s*:\s*(\d+)-(\d+)/i);
  if (srgb) model.protocols.mpls.sr.srgb = { start: toInt(srgb[1]), end: toInt(srgb[2]) };
  const srlb = b.match(/SRLB\s*:\s*(\d+)-(\d+)/i);
  if (srlb) model.protocols.mpls.sr.srlb = { start: toInt(srlb[1]), end: toInt(srlb[2]) };
}
function p_display_mpls_lsp_statistics(b, model) {
  const srbe = b.match(/srbe-lsp\s*[: ]\s*(\d+)/i) || b.match(/SR\s*BE.*?(\d+)/i);
  if (srbe) model.protocols.mpls.sr.lsp_stats.srbe = toInt(srbe[1]);
}
function p_display_tunnel_info_statistics(b, model) {
  const srbe = b.match(/srbe-lsp\s+(\d+)/i);
  if (srbe) model.protocols.mpls.sr.lsp_stats.srbe = toInt(srbe[1]);
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
        model.protocols.vrfs.push({ name, af });
      }
    }
  }
}
function p_display_ip_routing_table_statistics(b, model) {
  const vrf = (b.match(/VPN-Instance\s*:\s*([^\n\r]+)/i) || [])[1];
  const total = b.match(/Total\s+(\d+)/i);
  const sum = b.match(/Summary\s+Prefixes\s*[: ]\s*(\d+)/i);
  if (total || sum)
    model.routing.table_summary.push({
      vrf: vrf ? vrf.trim() : null,
      total_routes: total ? toInt(total[1]) : null,
      summary_prefixes: sum ? toInt(sum[1]) : null
    });
}

// ---------- Route map ----------
const ROUTES = [
  // identity/software/time/patch/ntp
  [/^display\s+version/i, p_display_version],
  [/^display\s+router\s+id\s+vpn-instance/i, p_display_router_id_vrf],
  [/^display\s+router\s+id/i, p_display_router_id],
  [/^display\s+clock/i, p_display_clock],
  [/^display\s+patch-information/i, p_display_patch_information],
  [/^display\s+startup/i, p_display_startup],
  [/^display\s+ntp.*status/i, p_display_ntp_status],
  [/^display\s+ntp.*unicast.*server/i, p_display_ntp_unicast],

  // resources
  [/^display\s+cpu-usage/i, p_display_cpu_usage],
  [/^display\s+health\s+verbose/i, p_display_health_verbose],
  [/^dir\s+cfcard::/i, p_dir_cfcard],
  [/^display\s+device\s+\d+\b/i, p_display_power_any],
  [/^display\s+power(\b|$)/i, p_display_power_any],
  [/^display\s+temperature/i, p_display_temperature],
  [/^display\s+fan/i, p_display_fan],
  [/^display\s+alarm\s+active\s+verbose/i, p_display_alarm_all],
  [/^display\s+alarm(\s|$)/i, p_display_alarm_all],

  // hardware / optics
  [/^display\s+device\s+pic-status/i, p_display_device_pic_status],
  [/^display\s+device(\s|$)/i, p_display_device],
  [/^display\s+elabel/i, p_display_elabel],
  [/^display\s+optical-module\s+(verbose|brief)/i, p_display_optical_module_any],

  // interfaces
  [/^display\s+interface\s+ethernet\s+brief/i, p_display_interface_ethernet_brief],
  [/^display\s+interface\s+brief/i, p_display_interface_brief],
  [/^display\s+ip\s+interface/i, p_display_ip_interface],
  [/^display\s+current-configuration/i, p_display_current_configuration],

  // protocols
  [/^display\s+arp\s+all/i, p_display_arp_all],
  [/^display\s+arp\s+statistics/i, p_display_arp_statistics],
  [/^display\s+mac-address\s+(dynamic|summary)/i, p_display_mac_address_any],
  [/^display\s+vlan(\s|$)/i, p_display_vlan],
  [/^display\s+vxlan(\s|$)/i, p_display_vxlan],
  [/^display\s+eth-trunk(\s|$)/i, p_display_eth_trunk],
  [/^display\s+lacp\s+peer/i, p_display_lacp_peer],
  [/^display\s+bfd\s+session/i, p_display_bfd_session_all],
  [/^display\s+bfd\s+configuration/i, p_display_bfd_configuration_all],
  [/^display\s+ospf\s+peer\s+brief/i, p_display_ospf_peer_brief],
  [/^display\s+ospf\s+brief/i, p_display_ospf_brief],
  [/^display\s+segment-routing/i, p_display_segment_routing],
  [/^display\s+mpls\s+lsp\s+statistics/i, p_display_mpls_lsp_statistics],
  [/^display\s+tunnel-info\s+statistics/i, p_display_tunnel_info_statistics],
  [/^display\s+bgp\s+peer/i, p_display_bgp_peer],
  [/^display\s+bgp\s+vpnv4.*peer/i, p_display_bgp_vpnv4_peer],
  [/^display\s+vpn-instance/i, p_display_vpn_instance],
  [/^display\s+ip\s+routing-table\s+statistics/i, p_display_ip_routing_table_statistics],

  // licenses
  [/^display\s+license\s+esn/i, p_display_license_esn],
  [/^display\s+license\s+verbose/i, p_display_license_verbose],
];

// ---------- Parse One File ----------
function parseFile(inFile) {
  const raw = fs.readFileSync(inFile, "utf8");
  const model = newModel();

  // hostname
  const hn = raw.match(/^<([^>]+)>/m);
  if (hn) model.identity.hostname = hn[1];

  const blk = splitBlocks(raw);
  for (const block of blk) {
    const cmd = detectCommand(block);
    let handled = false;
    for (const [rx, fn] of ROUTES) {
      if (rx.test(cmd)) {
        try {
          fn(block, model);
        } catch (e) {
          const key = normalizeKey(cmd);
          (model.raw_sections[key] ||= []).push({ error: e.message, raw: cleanTailPrompt(block) });
        }
        handled = true;
        break;
      }
    }
    if (!handled) {
      const key = normalizeKey(cmd);
      (model.raw_sections[key] ||= []).push({ raw: cleanTailPrompt(block) });
    }
  }

  // dedupe users
  model.identity.ssh_users = uniq(model.identity.ssh_users);

  // write output
  ensureOutDir();
  const outFile = outPathFor(inFile);

  // console summary
  console.log("\n✅ Parsed:", path.basename(inFile));
  console.log("→ Output :", outFile);
  console.log("— Hostname      :", model.identity.hostname || model.identity.sysname || "N/A");
  console.log("— Model         :", model.identity.model || "N/A");
  console.log("— Version       :", model.software.version || "N/A");
  console.log("— Uptime        :", model.software.uptime || "N/A");
  console.log("— Serial (ESN)  :", model.identity.serial || "N/A");
  console.log("— Router ID Pub :", model.identity.router_id_public || "N/A");
  console.log("— TZ / Now      :", model.identity.timezone || "N/A", "/", model.identity.current_time || "N/A");
  console.log("— NTP servers   :", (model.ntp.servers || []).join(", ") || "N/A");
  console.log("— CPU samples   :", model.resources.cpu.length);
  console.log("— Mem samples   :", model.resources.memory.length);
  console.log("— Disk samples  :", model.resources.disk.length);
  console.log("— PSU entries   :", model.resources.power.length);
  console.log("— Temps / Fans  :", model.resources.temperature.length, "/", model.resources.fan.length);
  console.log("— Cards / PICs  :", model.hardware.cards.length, "/", model.hardware.pics.length);
  console.log("— E-Labels / SFP:", model.hardware.elabels.length, "/", model.hardware.sfp.length);
  console.log("— Interfaces    :", model.interfaces.length);
  console.log("— ARP / MAC     :", model.protocols.arp.length, "/", model.protocols.mac.length);
  console.log("— VLANs / Trunk :", model.protocols.vlans.length, "/", model.protocols.trunks.length);
  console.log("— BFD / OSPF    :", model.protocols.bfd.sessions.length, "/", model.protocols.ospf.neighbors.length);
  console.log("— SRBE count    :", model.protocols.mpls.sr.lsp_stats.srbe || 0);
  console.log("— Route summary :", model.routing.table_summary.length);
  console.log("— Static routes :", model.routing.static.length);
  console.log("— Alarms        :", model.alarms.length);

  fs.writeFileSync(outFile, JSON.stringify(model, null, 2), "utf8");

  // Return the parsed model for programmatic use
  return model;
}

// Export parseFile so the analyzer can be required programmatically
module.exports = parseFile;
module.exports.parseFile = parseFile;

// Run as CLI only when invoked directly
if (require.main === module) {
  if (DIR_MODE) {
    const dir = path.resolve(DIR_PATH);
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
      console.error("❌ --dir is not a directory:", dir);
      process.exit(1);
    }
    const files = fs.readdirSync(dir).filter(f => f.toLowerCase().endsWith(".txt"));
    if (!files.length) {
      console.error("⚠️  No *.txt files in:", dir);
      process.exit(1);
    }
    console.log("📂 Scanning directory:", dir, "files:", files.length);
    ensureOutDir();
    for (const f of files) parseFile(path.join(dir, f));
  } else {
    const file = FILE_PATH ? path.resolve(FILE_PATH) : DEFAULT_FILE;
    if (!fs.existsSync(file)) {
      console.error("❌ Input file not found:", file);
      process.exit(1);
    }
    console.log("🔍 Parsing:", file);
    ensureOutDir();
    parseFile(file);
  }
}