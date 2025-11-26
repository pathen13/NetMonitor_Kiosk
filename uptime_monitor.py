import os
import time
import threading
import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, Response

# === Konfiguration ===
NETWORK_CIDR = os.getenv("NETWORK_CIDR", "192.168.178.0/24")
SCAN_INTERVAL_SECONDS = 30
MAX_WORKERS = 64
OFFLINE_FORGET_SECONDS = 300
KNOWN_HOSTS_FILE = os.getenv("KNOWN_HOSTS_FILE", "known_hosts.txt")
NEW_DEVICE_WINDOW_MINUTES = 5
NEW_DEVICE_WINDOW_SECONDS = NEW_DEVICE_WINDOW_MINUTES * 60

# devices: ip -> dict(...)
#   ip, hostname, required, vip, from_known_hosts,
#   first_seen, last_seen, online, created_at,
#   seen_before_baseline (optional)
devices = {}
devices_lock = threading.Lock()
# Wird nach dem ersten vollständigen Scan auf True gesetzt
baseline_done = False

app = Flask(__name__)


# -------- Ping & Known Hosts --------

def ping_ip(ip: str, timeout_ms: int = 1000) -> bool:
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            timeout_s = max(1, int(timeout_ms / 1000))
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def load_known_hosts(path: str):
    """
    Format:
      ip,hostname,required(true/false),vip(true/false)
    vip ist optional (wenn fehlt -> False).
    """
    info = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 3:
                    continue

                ip = parts[0]
                hostname = parts[1]
                req_str = parts[2].lower()
                required = req_str in ("true", "1", "yes", "ja")

                vip = False
                if len(parts) >= 4:
                    vip_str = parts[3].lower()
                    vip = vip_str in ("true", "1", "yes", "ja")

                info[ip] = {
                    "hostname": hostname,
                    "required": required,
                    "vip": vip,
                }
    except FileNotFoundError:
        print(f"WARN: {path} not found; continuing without predefined hosts")
    return info


known_hosts_info = load_known_hosts(KNOWN_HOSTS_FILE)

# Netzbereich + bekannte Hosts scannen
network = ipaddress.ip_network(NETWORK_CIDR, strict=False)
hosts = [str(h) for h in network.hosts()]

host_set = set(hosts)
host_set.update(known_hosts_info.keys())
hosts = sorted(host_set, key=lambda ip: int(ipaddress.ip_address(ip)))

# devices initial mit known_hosts füllen
now_init = time.time()
with devices_lock:
    for ip, info in known_hosts_info.items():
        devices[ip] = {
            "ip": ip,
            "hostname": info["hostname"],
            "required": info["required"],
            "vip": info.get("vip", False),
            "from_known_hosts": True,
            "first_seen": None,
            "last_seen": None,
            "online": False,
            "created_at": now_init,
            # wird später bei der Baseline gesetzt
        }


# -------- Scan-Logik --------

def scan_host(ip: str):
    ok = ping_ip(ip, timeout_ms=1000)
    now = time.time()
    with devices_lock:
        entry = devices.get(ip)

        if ok:
            # Host antwortet
            if entry is None:
                # neues dynamisches Gerät
                devices[ip] = {
                    "ip": ip,
                    "hostname": None,
                    "required": False,
                    "vip": False,
                    "from_known_hosts": False,
                    "first_seen": now,
                    "last_seen": now,
                    "online": True,
                    "created_at": now,
                    # seen_before_baseline wird hier bewusst NICHT gesetzt
                }
            else:
                if entry.get("first_seen") is None:
                    entry["first_seen"] = now
                entry["last_seen"] = now
                entry["online"] = True
        else:
            # keine Antwort
            if entry is None:
                # offline & unbekannt -> ignorieren
                return
            else:
                entry["online"] = False


def scan_loop():
    global baseline_done
    first_iteration = True

    while True:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(scan_host, hosts)

        now = time.time()
        with devices_lock:
            # Beim allerersten kompletten Scan:
            # alle zu diesem Zeitpunkt bekannten Geräte als "Baseline" markieren.
            if first_iteration and not baseline_done:
                for d in devices.values():
                    d["seen_before_baseline"] = True
                baseline_done = True
                first_iteration = False

            # Aufräumen: unbekannte, lange offline Geräte
            to_delete = []
            for ip, d in list(devices.items()):
                if d.get("from_known_hosts") or d.get("required"):
                    continue
                if d.get("online"):
                    continue
                base = d.get("last_seen") or d.get("created_at") or now
                if now - base > OFFLINE_FORGET_SECONDS:
                    to_delete.append(ip)
            for ip in to_delete:
                del devices[ip]

        time.sleep(SCAN_INTERVAL_SECONDS)


# -------- Web-UI (800x240, 6 Kästen/Zeile) --------

@app.route("/")
def index():
    html = """
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Uptime Monitor</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    html, body {
      margin: 0;
      padding: 0;
      width: 100%;
      height: 100%;
      background: #111;
      color: #eee;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      overflow: hidden;
      font-size: 0.9rem;
    }
    .header {
      padding: 2px 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #000;
      box-shadow: 0 2px 4px rgba(0,0,0,0.7);
      z-index: 10;
    }
    .header h1 {
      margin: 0;
      font-size: 0.95rem;
      font-weight: 500;
    }
    .header .info {
      font-size: 0.75rem;
      opacity: 0.8;
      text-align: right;
      line-height: 1.1;
    }
    .container {
      position: absolute;
      top: 28px;
      left: 0;
      right: 0;
      bottom: 0;
      padding: 2px 4px;
      box-sizing: border-box;
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
      grid-auto-rows: minmax(34px, auto);
      gap: 4px;
      overflow: auto;
    }
    .bubble {
      width: 100%;
      height: 100%;
      border-radius: 4px;
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      justify-content: center;
      text-align: left;
      padding: 2px 4px;
      box-sizing: border-box;
      box-shadow: 0 0 3px rgba(0,0,0,0.6);
      transition: transform 0.1s ease, box-shadow 0.1s ease;
    }
    .bubble:hover {
      transform: translateY(-1px);
      box-shadow: 0 0 6px rgba(0,0,0,0.9);
    }

    /* Farben / States */
    .bubble.online {
      background-color: #4caf50;      /* normal online */
    }
    .bubble.offline-required {
      background-color: #b71c1c;      /* required & offline */
    }
    .bubble.new-online {
      background-color: #2196f3;      /* neu & online */
    }
    .bubble.vip-online {
      background-color: #1d471c;      /* VIP online */
    }

    .hostname {
      font-size: 0.8rem;
      font-weight: 600;
      margin-bottom: 1px;
      word-break: break-word;
    }
    .ip {
      font-size: 0.7rem;
      opacity: 0.9;
    }
    .status {
      margin-top: 1px;
      font-size: 0.65rem;
      opacity: 0.85;
    }

    @keyframes blink {
      0%, 50%, 100% { opacity: 1; }
      25%, 75% { opacity: 0.3; }
    }
    .blink {
      animation: blink 1s infinite;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Uptime Monitor</h1>
    <div class="info">
      Netz: <span id="net"></span><br>
      Geräte: <span id="count">0</span> · <span id="ts">-</span>
    </div>
  </div>
  <div class="container" id="bubbles"></div>

<script>
  const REFRESH_INTERVAL_MS = 5000;

  function formatAge(seconds) {
    if (seconds == null) return "-";
    const s = Math.floor(seconds);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const r = s % 60;
    if (h > 0) return h + "h " + m + "m";
    if (m > 0) return m + "m " + r + "s";
    return r + "s";
  }

  async function loadDevices() {
    try {
      const res = await fetch("/api/devices");
      const data = await res.json();

      const container = document.getElementById("bubbles");
      container.innerHTML = "";

      document.getElementById("net").textContent = data.network;
      document.getElementById("count").textContent = data.devices.length;
      document.getElementById("ts").textContent = new Date().toLocaleTimeString();

      data.devices.forEach(dev => {
        const bubble = document.createElement("div");
        const classes = ["bubble"];

        // Farb-/Blink-Logik:
        if (dev.online) {
          if (dev.vip) {
            classes.push("vip-online");
            if (dev.is_new) {
              classes.push("blink");  // neuer VIP -> blinkt
            }
          } else if (dev.is_new) {
            classes.push("new-online", "blink");
          } else {
            classes.push("online");
          }
        } else {
          if (dev.required) {
            classes.push("offline-required", "blink");
          }
          // offline & nicht required / VIP offline werden gar nicht geliefert
        }

        bubble.className = classes.join(" ");

        const hostname = document.createElement("div");
        hostname.className = "hostname";
        hostname.textContent = dev.hostname || dev.ip;

        const ip = document.createElement("div");
        ip.className = "ip";
        if (dev.hostname) {
          ip.textContent = dev.ip;
        } else {
          ip.textContent = "";
        }

        const status = document.createElement("div");
        status.className = "status";
        if (dev.online) {
          status.textContent = "online seit " + formatAge(dev.age_seconds);
        } else if (dev.last_seen_seconds_ago != null) {
          status.textContent = "offline seit " + formatAge(dev.last_seen_seconds_ago);
        } else {
          status.textContent = "offline (noch nie erreicht)";
        }

        bubble.appendChild(hostname);
        if (ip.textContent) bubble.appendChild(ip);
        bubble.appendChild(status);

        container.appendChild(bubble);
      });
    } catch (e) {
      console.error("Fehler beim Laden der Geräte", e);
    }
  }

  loadDevices();
  setInterval(loadDevices, REFRESH_INTERVAL_MS);
</script>
</body>
</html>
"""
    return Response(html, mimetype="text/html")


# -------- API (Sortierung + Filter + "neu" nach Baseline) --------

@app.route("/api/devices")
def api_devices():
    now = time.time()
    with devices_lock:
        result = []
        for ip, d in devices.items():
            online = d.get("online", False)
            required = d.get("required", False)
            from_known = d.get("from_known_hosts", False)
            vip = d.get("vip", False)

            # Filter:
            if not online:
                # VIP offline -> nicht anzeigen
                if vip:
                    continue
                # offline & nicht required -> nicht anzeigen
                if not required:
                    continue
                # offline & nicht aus known_hosts -> nicht anzeigen
                if not from_known:
                    continue

            first_seen = d.get("first_seen")
            last_seen = d.get("last_seen")

            age = now - first_seen if first_seen is not None else None
            last_seen_ago = now - last_seen if last_seen is not None else None
            seen_before_baseline = d.get("seen_before_baseline", False)

            # "neu" nur für Geräte, die NACH der Baseline hinzugekommen sind
            is_new = bool(
                online and
                first_seen is not None and
                baseline_done and
                not seen_before_baseline and
                age is not None and
                age <= NEW_DEVICE_WINDOW_SECONDS
            )

            # Sortier-Gruppen:
            # 0: known_hosts + required
            # 1: VIP online
            # 2: neue Geräte
            # 3: Rest
            if from_known and required:
                group = 0
            elif vip and online:
                group = 1
            elif is_new:
                group = 2
            else:
                group = 3

            result.append({
                "ip": ip,
                "hostname": d.get("hostname"),
                "required": required,
                "vip": vip,
                "online": online,
                "age_seconds": age,
                "last_seen_seconds_ago": last_seen_ago,
                "is_new": is_new,
                "group": group,
            })

        result.sort(key=lambda dev: (dev["group"], ipaddress.ip_address(dev["ip"])))

    for dev in result:
        dev.pop("group", None)

    return jsonify({
        "network": NETWORK_CIDR,
        "devices": result,
    })


def start_scanner():
    t = threading.Thread(target=scan_loop, daemon=True)
    t.start()


if __name__ == "__main__":
    start_scanner()
    app.run(host="0.0.0.0", port=8000)
