package com.honeypot.app;

import com.honeypot.exception.BlacklistedIPException;
import com.honeypot.io.ForensicLogger;
import com.honeypot.model.AbstractSensor;
import com.honeypot.model.AlertListener;
import com.honeypot.model.ThreatEvent;
import com.honeypot.network.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;

public class WebDashboardApp {
    private static final String[][] DECOY_BANNERS = {
        {"2222", "SSH-2.0-OpenSSH_8.9p1 Gov-Gateway"},
        {"8080", "HTTP/1.1 200 OK\r\nServer: Gov-Portal-Admin/2.4\r\nContent-Type: text/html\r\n\r\n<h2>Gov-Portal Restricted Endpoint (Decoy Port 8080)</h2><p>Unauthorized probe logged.</p>"},
        {"2121", "220 Gov-FTP Evidence Archive Server Ready"}
    };

    private static final List<ThreatEvent> recentAlerts = Collections.synchronizedList(new LinkedList<>());

    private static String lookupBanner(int port) {
        for (String[] row : DECOY_BANNERS) {
            if (Integer.parseInt(row[0]) == port) return row[1];
        }
        return "220 Generic Decoy Honeypot Service";
    }

    public static void main(String[] args) throws IOException {
        Properties config = new Properties();
        String configPath = (args.length > 0) ? args[0] : "config/honeypot.properties";
        try (FileInputStream fis = new FileInputStream(configPath)) {
            config.load(fis);
        } catch (IOException e) {
            System.out.println("[WARN] Using default config.");
        }

        String portEnv = System.getenv("PORT");
        int webPort = (portEnv != null && !portEnv.trim().isEmpty()) ? Integer.parseInt(portEnv.trim()) : 8000;

        String tcpPortsProp = config.getProperty("tcp.ports", "2222,8080,2121");
        int udpPort = Integer.parseInt(config.getProperty("udp.port", "9090"));
        String logDir = config.getProperty("log.dir", "logs");
        String blacklistFile = config.getProperty("blacklist.file", "config/blacklist.txt");

        String lanIp = detectLocalLanIp();

        ForensicLogger logger = new ForensicLogger(logDir);
        Vector<String> blacklist = logger.loadBlacklist(blacklistFile);
        ThreatMonitorQueue threatQueue = new ThreatMonitorQueue(blacklist);

        AlertListener webAlertHandler = new AlertListener() {
            @Override
            public void onThreatDetected(ThreatEvent event) {
                logger.logEvent(event);
                synchronized (recentAlerts) {
                    recentAlerts.add(0, event);
                    if (recentAlerts.size() > 60) {
                        recentAlerts.remove(recentAlerts.size() - 1);
                    }
                }
                System.out.println("[LIVE-SOC] " + event.toString());
            }

            @Override
            public String formatForAuditLog() {
                return "WebDashboardAlertHandler";
            }
        };

        AlertDispatcherThread dispatcher = new AlertDispatcherThread(threatQueue, webAlertHandler);
        dispatcher.start();

        List<AbstractSensor> sensors = new ArrayList<>();
        for (String token : tcpPortsProp.split(",")) {
            try {
                int port = Integer.parseInt(token.trim());
                if (port == webPort) continue;
                TCPSensor tcpSensor = new TCPSensor(port, lookupBanner(port), threatQueue);
                sensors.add(tcpSensor);
                new Thread(tcpSensor, "Thread-TCP-" + port).start();
            } catch (NumberFormatException ignored) {}
        }

        UDPSensor udpSensor = new UDPSensor(udpPort, threatQueue);
        sensors.add(udpSensor);
        new Thread(udpSensor, "Thread-UDP-" + udpPort).start();

        logger.logEvent("Live Web SOC Dashboard started on " + lanIp + ":" + webPort);

        // Bind to 0.0.0.0 so external laptops/phones on LAN or Hotspot can connect
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", webPort), 0);

        // 1. Defender SOC Dashboard (Your Laptop / Projector)
        server.createContext("/", exchange -> {
            byte[] html = buildSocDashboardHtml(lanIp, webPort).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, html.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(html);
            }
        });

        // 2. Fake Decoy Government Portal (For Teammate / External Attacker Browser)
        server.createContext("/portal", exchange -> {
            String remoteIp = getClientIp(exchange);
            byte[] html = buildAttackerPortalHtml(lanIp, webPort, remoteIp).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, html.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(html);
            }
        });

        // 3. Real External Attack Endpoint (Captures Attacker's Real IP & Enforces Blacklist)
        server.createContext("/api/portal-hit", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            String attackType = getQueryParam(query, "type");
            String payloadText = getQueryParam(query, "payload");
            if (payloadText.isEmpty()) payloadText = "UNAUTHORIZED_ACCESS_ATTEMPT";

            String remoteIp = getClientIp(exchange);
            byte[] rawBytes = payloadText.getBytes(StandardCharsets.UTF_8);

            try {
                // Unit 3 & 5: Check Vector blacklist -> throws BlacklistedIPException if blocked
                threatQueue.verifyIpNotBlacklisted(remoteIp);

                String severity = classifyWebSeverity(attackType, payloadText);
                String protoLabel = "HTTP-PORTAL";
                ThreatEvent event = new ThreatEvent(protoLabel, remoteIp, webPort, severity, rawBytes);
                threatQueue.pushThreat(event);

                String resp = "{\"blocked\":false,\"ip\":\"" + escapeJson(remoteIp)
                        + "\",\"severity\":\"" + severity
                        + "\",\"message\":\"Access Denied (Decoy Trap Logged Your IP & Payload)\"}";
                sendJson(exchange, 200, resp);
            } catch (BlacklistedIPException bEx) {
                byte[] combined = (bEx.getMessage() + " | Raw: " + payloadText).getBytes(StandardCharsets.UTF_8);
                ThreatEvent blockedEvent = new ThreatEvent("HTTP-PORTAL", remoteIp, webPort, "CRITICAL", combined);
                threatQueue.pushThreat(blockedEvent);

                String resp = "{\"blocked\":true,\"ip\":\"" + escapeJson(remoteIp)
                        + "\",\"severity\":\"CRITICAL\",\"message\":\"CONNECTION REJECTED: Your IP ("
                        + escapeJson(remoteIp) + ") is BLACKLISTED by Cyber Honeypot IDS!\"}";
                sendJson(exchange, 403, resp);
            }
        });

        // 4. Live State JSON API for Defender Dashboard
        server.createContext("/api/state", exchange -> {
            sendJson(exchange, 200, buildStateJson(sensors, threatQueue, logger, lanIp, webPort));
        });

        // 5. Block IP API (Live containment)
        server.createContext("/api/block", exchange -> {
            String ip = getQueryParam(exchange.getRequestURI().getQuery(), "ip").trim();
            if (!ip.isEmpty()) {
                threatQueue.addToBlacklist(ip);
                logger.logEvent("SOC operator BLOCKED IP: " + ip);
                sendJson(exchange, 200, "{\"status\":\"blocked\",\"ip\":\"" + escapeJson(ip) + "\"}");
            } else {
                sendJson(exchange, 400, "{\"error\":\"IP required\"}");
            }
        });

        // 6. Unblock IP API (Handy for resetting demo before/during presentation)
        server.createContext("/api/unblock", exchange -> {
            String ip = getQueryParam(exchange.getRequestURI().getQuery(), "ip").trim();
            if (!ip.isEmpty()) {
                threatQueue.getBlacklistedIps().remove(ip);
                logger.logEvent("SOC operator UNBLOCKED IP: " + ip);
                sendJson(exchange, 200, "{\"status\":\"unblocked\",\"ip\":\"" + escapeJson(ip) + "\"}");
            } else {
                sendJson(exchange, 400, "{\"error\":\"IP required\"}");
            }
        });

        // 7. Quick Local Socket Self-Test API (Tests TCP 2222/8080/2121 & UDP 9090)
        server.createContext("/api/attack", exchange -> {
            String type = getQueryParam(exchange.getRequestURI().getQuery(), "type");
            if ("ssh".equals(type)) {
                fireTcp("127.0.0.1", 2222, "USER root PASS toor123\r\n");
            } else if ("sqli".equals(type)) {
                fireTcp("127.0.0.1", 8080, "GET /admin?id=1' OR '1'='1'; DROP TABLE users;-- HTTP/1.1\r\n");
            } else if ("ftp".equals(type)) {
                fireTcp("127.0.0.1", 2121, "");
            } else if ("udp".equals(type)) {
                fireUdp("127.0.0.1", udpPort, "UDP_RECON_PROBE:SCAN_SUBNET");
            }
            sendJson(exchange, 200, "{\"status\":\"dispatched\",\"type\":\"" + escapeJson(type) + "\"}");
        });

        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();

        System.out.println("=================================================================");
        System.out.println("   MULTI-THREADED CYBER HONEYPOT & LIVE IDS - READY FOR DEMO     ");
        System.out.println("=================================================================");
        System.out.println("  [1] YOUR SOC DASHBOARD (Open on Laptop) :");
        System.out.println("      http://localhost:" + webPort);
        System.out.println("      http://" + lanIp + ":" + webPort);
        System.out.println();
        System.out.println("  [2] TEAMMATE ATTACK PORTAL (Open on Phone / 2nd Laptop) :");
        System.out.println("      http://" + lanIp + ":" + webPort + "/portal");
        System.out.println();
        System.out.println("  [3] DIRECT DECOY TCP PORT (Browser / curl / Simulator) :");
        System.out.println("      http://" + lanIp + ":8080/admin?user=root&q=DROP_TABLE");
        System.out.println("=================================================================");
    }

    private static String getClientIp(HttpExchange exchange) {
        String xff = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xff != null && !xff.trim().isEmpty()) {
            return xff.split(",")[0].trim();
        }
        String ip = exchange.getRemoteAddress().getAddress().getHostAddress();
        if ("0:0:0:0:0:0:0:1".equals(ip)) return "127.0.0.1";
        return ip;
    }

    private static String detectLocalLanIp() {
        String fallback = "127.0.0.1";
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics.hasMoreElements()) {
                NetworkInterface ni = nics.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                String name = ni.getDisplayName().toLowerCase();
                boolean isVirtual = name.contains("virtual") || name.contains("vbox")
                        || name.contains("vmware") || name.contains("hyper-v") || name.contains("wsl");
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        String ip = addr.getHostAddress();
                        if (!isVirtual && (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172."))) {
                            return ip;
                        }
                        if ("127.0.0.1".equals(fallback)) fallback = ip;
                    }
                }
            }
        } catch (SocketException ignored) {}
        return fallback;
    }

    private static String classifyWebSeverity(String type, String payload) {
        String combined = (type + " " + payload).toLowerCase();
        if (combined.contains("sqli") || combined.contains("drop") || combined.contains("union")
                || combined.contains("admin") || combined.contains("root") || combined.contains("brute")
                || combined.contains("passwd")) {
            return "HIGH";
        }
        return "MEDIUM";
    }

    private static void fireTcp(String host, int port, String payload) {
        new Thread(() -> {
            try (Socket s = new Socket(host, port)) {
                s.setSoTimeout(1500);
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                in.readLine();
                if (!payload.isEmpty()) {
                    OutputStream out = s.getOutputStream();
                    out.write(payload.getBytes(StandardCharsets.UTF_8));
                    out.flush();
                }
            } catch (IOException ignored) {}
        }).start();
    }

    private static void fireUdp(String host, int port, String msg) {
        new Thread(() -> {
            try (DatagramSocket ds = new DatagramSocket()) {
                byte[] data = msg.getBytes(StandardCharsets.UTF_8);
                DatagramPacket pkt = new DatagramPacket(data, data.length, InetAddress.getByName(host), port);
                ds.send(pkt);
            } catch (IOException ignored) {}
        }).start();
    }

    private static String buildStateJson(List<AbstractSensor> sensors, ThreatMonitorQueue queue,
                                         ForensicLogger logger, String lanIp, int webPort) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"serverIp\":\"").append(escapeJson(lanIp)).append("\",");
        sb.append("\"webPort\":").append(webPort).append(",");
        sb.append("\"totalSensors\":").append(AbstractSensor.SensorStats.getTotalSensors()).append(",");
        sb.append("\"logFolderBytes\":").append(logger.calculateLogFolderSize(logger.getLogDir())).append(",");
        sb.append("\"rawPayloadBytes\":").append(logger.countRawPayloadBytes()).append(",");

        sb.append("\"sensors\":[");
        for (int i = 0; i < sensors.size(); i++) {
            AbstractSensor s = sensors.get(i);
            if (i > 0) sb.append(",");
            sb.append("{\"id\":\"").append(escapeJson(s.getSensorId()))
              .append("\",\"protocol\":\"").append(escapeJson(s.getProtocolName()))
              .append("\",\"port\":").append(s.getPort())
              .append(",\"state\":\"").append(escapeJson(s.getStateSummary())).append("\"}");
        }
        sb.append("],");

        sb.append("\"blacklist\":[");
        Enumeration<String> en = queue.getBlacklistedIps().elements();
        int bIdx = 0;
        while (en.hasMoreElements()) {
            if (bIdx++ > 0) sb.append(",");
            sb.append("\"").append(escapeJson(en.nextElement())).append("\"");
        }
        sb.append("],");

        sb.append("\"alerts\":[");
        synchronized (recentAlerts) {
            for (int i = 0; i < recentAlerts.size(); i++) {
                ThreatEvent e = recentAlerts.get(i);
                if (i > 0) sb.append(",");
                sb.append("{\"severity\":\"").append(escapeJson(e.getSeverity()))
                  .append("\",\"protocol\":\"").append(escapeJson(e.getProtocol()))
                  .append("\",\"ip\":\"").append(escapeJson(e.getSourceIp()))
                  .append("\",\"port\":").append(e.getTargetPort())
                  .append(",\"payload\":\"").append(escapeJson(e.getPayloadPreview()))
                  .append("\",\"log\":\"").append(escapeJson(e.formatForAuditLog())).append("\"}");
            }
        }
        sb.append("]}");
        return sb.toString();
    }

    private static void sendJson(HttpExchange exchange, int code, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String getQueryParam(String query, String key) {
        if (query == null) return "";
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(key)) {
                try {
                    return URLDecoder.decode(kv[1], "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    return kv[1];
                }
            }
        }
        return "";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // =========================================================================
    // FRONTEND 1: DEFENDER LIVE SOC DASHBOARD (OPEN ON YOUR LAPTOP / PROJECTOR)
    // =========================================================================
    private static String buildSocDashboardHtml(String lanIp, int webPort) {
        String portalUrl = "http://" + lanIp + ":" + webPort + "/portal";
        String decoy8080 = "http://" + lanIp + ":8080/admin?user=root&q=DROP_TABLE";
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + "<title>Cyber Honeypot IDS — Live SOC Console</title>"
            + "<style>"
            + "*{box-sizing:border-box;}body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:#060c18;color:#e2e8f0;padding:18px;}"
            + ".wrap{max-width:1200px;margin:auto;}"
            + ".topbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;background:#0d172a;border:1px solid #1e293b;border-radius:12px;padding:16px 20px;margin-bottom:16px;}"
            + ".title{font-size:22px;font-weight:800;color:#38bdf8;margin:0;}"
            + ".sub{font-size:13px;color:#94a3b8;margin-top:3px;}"
            + ".live-pill{display:inline-flex;align-items:center;gap:8px;background:#052e16;border:1px solid #16a34a;color:#4ade80;padding:6px 14px;border-radius:99px;font-size:12px;font-weight:700;}"
            + ".dot{width:9px;height:9px;border-radius:50%;background:#22c55e;animation:pulse 1.3s infinite;}"
            + "@keyframes pulse{0%{opacity:1;}50%{opacity:.25;}100%{opacity:1;}}"
            + ".share-box{background:linear-gradient(90deg,#0f172a,#172554);border:1px solid #2563eb;border-radius:12px;padding:14px 18px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;}"
            + ".url-chip{background:#020617;border:1px solid #38bdf8;color:#7dd3fc;padding:7px 12px;border-radius:8px;font-family:Consolas,monospace;font-size:13px;font-weight:700;}"
            + ".grid4{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px;}"
            + ".grid2{display:grid;grid-template-columns:1.2fr 1fr;gap:14px;margin-bottom:16px;}"
            + "@media(max-width:850px){.grid2{grid-template-columns:1fr;}}"
            + ".card{background:#0d172a;border:1px solid #1e293b;border-radius:12px;padding:16px;}"
            + ".card h3{margin:0 0 10px;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.8px;}"
            + ".stat{font-size:26px;font-weight:800;color:#f8fafc;}"
            + ".stat-red{color:#f87171;}.stat-cyan{color:#38bdf8;}"
            + "table{width:100%;border-collapse:collapse;font-size:13px;}"
            + "th{text-align:left;padding:10px 8px;color:#94a3b8;border-bottom:1px solid #1e293b;font-size:11px;text-transform:uppercase;}"
            + "td{padding:10px 8px;border-bottom:1px solid #111c33;vertical-align:middle;}"
            + ".ip-tag{font-family:Consolas,monospace;font-weight:700;color:#fde047;background:#1e293b;padding:3px 8px;border-radius:6px;}"
            + ".payload{font-family:Consolas,monospace;color:#cbd5e1;font-size:12px;word-break:break-all;}"
            + ".badge{padding:3px 8px;border-radius:6px;font-size:11px;font-weight:800;display:inline-block;}"
            + ".CRITICAL{background:#7f1d1d;color:#fecaca;border:1px solid #ef4444;}"
            + ".HIGH{background:#991b1b;color:#fca5a5;}"
            + ".MEDIUM{background:#78350f;color:#fde68a;}"
            + ".LOW{background:#1e3a8a;color:#bfdbfe;}"
            + "button{border:none;border-radius:7px;padding:7px 12px;font-weight:700;cursor:pointer;font-size:12px;color:#fff;}"
            + ".b-red{background:#dc2626;}.b-amber{background:#d97706;}.b-blue{background:#2563eb;}.b-purple{background:#7c3aed;}.b-dark{background:#334155;}"
            + "button:hover{opacity:.88;}"
            + "input{background:#020617;border:1px solid #334155;color:#fff;padding:8px 10px;border-radius:8px;width:190px;font-family:Consolas,monospace;}"
            + ".pill{display:inline-flex;align-items:center;gap:6px;background:#1e293b;padding:5px 10px;border-radius:99px;font-size:12px;margin:4px 6px 0 0;color:#7dd3fc;}"
            + ".pill-red{background:#450a0a;border:1px solid #dc2626;color:#fca5a5;}"
            + ".unblock-x{background:#7f1d1d;color:#fff;padding:1px 6px;border-radius:99px;font-size:11px;margin-left:4px;cursor:pointer;}"
            + "</style></head><body><div class='wrap'>"
            + "<div class='topbar'><div><h1 class='title'>Multi-Threaded Cyber Honeypot &amp; Live IDS</h1>"
            + "<div class='sub'>Core Java SE — Real-Time Intrusion Capture, Dynamic IP Blacklisting &amp; Dual-Stream Forensics</div></div>"
            + "<div class='live-pill'><span class='dot'></span> LIVE MONITORING ACTIVE</div></div>"

            + "<div class='share-box'><div>"
            + "<div style='font-size:12px;color:#93c5fd;font-weight:700;margin-bottom:4px;'>STEP 1: OPEN THIS ON TEAMMATE'S PHONE OR 2ND LAPTOP (SAME HOTSPOT / WI-FI)</div>"
            + "<span class='url-chip' id='portalUrl'>" + portalUrl + "</span> "
            + "<button class='b-blue' onclick=\"navigator.clipboard.writeText('" + portalUrl + "')\">Copy Link</button>"
            + "</div><div style='font-size:12px;color:#cbd5e1;'>Direct TCP Decoy Port:<br><span style='font-family:Consolas,monospace;color:#fde047;'>" + decoy8080 + "</span></div></div>"

            + "<div class='grid4'>"
            + "<div class='card'><h3>Active Decoy Sensors</h3><div class='stat stat-cyan' id='sCount'>0</div></div>"
            + "<div class='card'><h3>Live Intrusions Logged</h3><div class='stat stat-red' id='aCount'>0</div></div>"
            + "<div class='card'><h3>Blacklisted IPs</h3><div class='stat' id='bCount'>0</div></div>"
            + "<div class='card'><h3>Forensic Evidence Disk</h3><div class='stat' id='logSize'>0 B</div></div>"
            + "</div>"

            + "<div class='grid2'>"
            + "<div class='card'><h3>Active Multi-Threaded Sensors + Local Socket Self-Test</h3>"
            + "<div id='sensors' style='margin-bottom:12px;'>Loading...</div>"
            + "<div style='display:flex;flex-wrap:wrap;gap:8px;'>"
            + "<button class='b-dark' onclick=\"localTest('ssh')\">Test SSH:2222</button>"
            + "<button class='b-dark' onclick=\"localTest('sqli')\">Test HTTP:8080</button>"
            + "<button class='b-dark' onclick=\"localTest('ftp')\">Test FTP:2121</button>"
            + "<button class='b-purple' onclick=\"localTest('udp')\">Test UDP:9090</button>"
            + "</div></div>"

            + "<div class='card'><h3>Live IP Blacklist (Thread-Safe Vector)</h3>"
            + "<div style='display:flex;gap:8px;margin-bottom:10px;'><input id='ipInput' placeholder='Enter Attacker IP'/>"
            + "<button class='b-red' onclick='blockManual()'>Block IP</button></div>"
            + "<div id='blacklist'></div></div>"
            + "</div>"

            + "<div class='card'><h3>Live Intrusion Feed (Auto-Refresh Every 1s — Click 'Block IP' on Any Real Attacker)</h3>"
            + "<div style='overflow-x:auto;max-height:420px;overflow-y:auto;'>"
            + "<table><thead><tr><th>Severity</th><th>Attacker Real IP</th><th>Protocol : Port</th><th>Captured Payload / Evidence</th><th>Action</th></tr></thead>"
            + "<tbody id='alertsBody'><tr><td colspan='5' style='color:#64748b;text-align:center;padding:24px;'>Waiting for incoming attacks... Open <b>" + portalUrl + "</b> on teammate's phone/laptop to trigger live demo.</td></tr></tbody>"
            + "</table></div></div>"

            + "</div><script>"
            + "let currentBlacklist = [];"
            + "function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}"
            + "async function blockIp(ip){await fetch('/api/block?ip='+encodeURIComponent(ip));loadState();}"
            + "async function unblockIp(ip){await fetch('/api/unblock?ip='+encodeURIComponent(ip));loadState();}"
            + "function blockManual(){const ip=document.getElementById('ipInput').value.trim();if(ip){blockIp(ip);document.getElementById('ipInput').value='';}}"
            + "async function localTest(t){await fetch('/api/attack?type='+t);setTimeout(loadState,350);}"
            + "async function loadState(){try{const r=await fetch('/api/state');const d=await r.json();"
            + "currentBlacklist=d.blacklist||[];"
            + "document.getElementById('sCount').textContent=d.totalSensors;"
            + "document.getElementById('aCount').textContent=d.alerts.length;"
            + "document.getElementById('bCount').textContent=currentBlacklist.length;"
            + "document.getElementById('logSize').textContent=d.logFolderBytes+' B (Raw: '+d.rawPayloadBytes+' B)';"
            + "document.getElementById('sensors').innerHTML=d.sensors.map(s=>'<span class=\"pill\">'+esc(s.state)+' • '+esc(s.protocol)+':'+s.port+'</span>').join('');"
            + "document.getElementById('blacklist').innerHTML=currentBlacklist.length?currentBlacklist.map(ip=>'<span class=\"pill pill-red\">'+esc(ip)+'<span class=\"unblock-x\" title=\"Unblock\" onclick=\"unblockIp(\\''+esc(ip)+'\\')\">x</span></span>').join(''):'<span style=\"color:#64748b;font-size:12px;\">No IPs blocked yet.</span>';"
            + "if(d.alerts.length){document.getElementById('alertsBody').innerHTML=d.alerts.map(a=>{"
            + "const isBlk=currentBlacklist.includes(a.ip);"
            + "const btn=isBlk?'<span class=\"badge CRITICAL\">BLOCKED</span>':'<button class=\"b-red\" onclick=\"blockIp(\\''+esc(a.ip)+'\\')\">Block IP</button>';"
            + "return '<tr><td><span class=\"badge '+esc(a.severity)+'\">'+esc(a.severity)+'</span></td>'"
            + "+'<td><span class=\"ip-tag\">'+esc(a.ip)+'</span></td>'"
            + "+'<td>'+esc(a.protocol)+':'+a.port+'</td>'"
            + "+'<td class=\"payload\">'+esc(a.payload)+'</td>'"
            + "+'<td>'+btn+'</td></tr>';}).join('');}"
            + "}catch(e){}}"
            + "loadState();setInterval(loadState,1000);"
            + "</script></body></html>";
    }

    // =========================================================================
    // FRONTEND 2: FAKE GOV PORTAL / TEAMMATE ATTACK CONSOLE (/portal)
    // =========================================================================
    private static String buildAttackerPortalHtml(String lanIp, int webPort, String visitorIp) {
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + "<title>National Gov-Admin Portal (Target Server)</title>"
            + "<style>"
            + "*{box-sizing:border-box;}body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:18px;}"
            + ".box{max-width:520px;margin:12px auto;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:22px;box-shadow:0 10px 30px rgba(0,0,0,.4);}"
            + ".hdr{text-align:center;border-bottom:1px solid #334155;padding-bottom:14px;margin-bottom:18px;}"
            + ".hdr h2{margin:0;color:#38bdf8;font-size:20px;}"
            + ".hdr p{margin:6px 0 0;font-size:12px;color:#94a3b8;}"
            + ".ip-banner{background:#020617;border:1px solid #334155;border-radius:8px;padding:9px 12px;font-size:12px;color:#cbd5e1;margin-bottom:16px;text-align:center;font-family:Consolas,monospace;}"
            + "label{display:block;font-size:12px;color:#94a3b8;margin-bottom:5px;}"
            + "input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#fff;margin-bottom:12px;font-size:14px;}"
            + "button{width:100%;padding:11px;border:none;border-radius:8px;font-weight:700;font-size:14px;cursor:pointer;color:#fff;margin-bottom:10px;}"
            + ".b-login{background:#2563eb;}.b-red{background:#dc2626;}.b-amber{background:#d97706;}.b-purple{background:#7c3aed;}"
            + "button:hover{opacity:.9;}"
            + ".sec-title{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#94a3b8;margin:16px 0 10px;border-top:1px solid #334155;padding-top:14px;}"
            + ".res{margin-top:14px;padding:14px;border-radius:10px;font-size:13px;font-weight:600;display:none;line-height:1.45;}"
            + ".res-warn{background:#451a03;border:1px solid #f59e0b;color:#fde68a;}"
            + ".res-blk{background:#450a0a;border:2px solid #ef4444;color:#fecaca;font-size:14px;text-align:center;}"
            + "</style></head><body><div class='box'>"
            + "<div class='hdr'><h2>GOV-PORTAL RESTRICTED ADMIN</h2>"
            + "<p>Target Server: " + lanIp + ":" + webPort + " (Simulated Government Portal)</p></div>"
            + "<div class='ip-banner'>Your Device IP: <b style='color:#fde047;'>" + visitorIp + "</b></div>"

            + "<label>Admin Username</label><input id='u' value='admin' placeholder='Username'/>"
            + "<label>Password / Exploit Input</label><input id='p' value=\"' OR '1'='1' --\" placeholder='Password'/>"
            + "<button class='b-login' onclick='submitLogin()'>Attempt Unauthorized Admin Login</button>"

            + "<div class='sec-title'>Quick Live Attack Payloads (From This Device)</div>"
            + "<button class='b-red' onclick=\"fire('sqli','GET /admin?id=1 OR 1=1; DROP TABLE citizens;--')\">1. Launch SQL Injection Attack (HIGH)</button>"
            + "<button class='b-amber' onclick=\"fire('brute','BRUTE_FORCE USER=root PASS=GovAdmin@2026')\">2. Launch Root Credential Brute-Force (HIGH)</button>"
            + "<button class='b-purple' onclick=\"fire('recon','SCAN /etc/passwd & /backup/db_dump.sql')\">3. Launch Sensitive File Recon Scan (HIGH)</button>"

            + "<div id='res' class='res'></div>"
            + "</div><script>"
            + "function submitLogin(){const u=document.getElementById('u').value;const p=document.getElementById('p').value;"
            + "fire('login','LOGIN_ATTEMPT USER='+u+' PASS='+p);}"
            + "async function fire(type,payload){const box=document.getElementById('res');box.style.display='block';"
            + "try{const r=await fetch('/api/portal-hit?type='+encodeURIComponent(type)+'&payload='+encodeURIComponent(payload));"
            + "const d=await r.json();"
            + "if(r.status===403||d.blocked){box.className='res res-blk';box.innerHTML='ACCESS BLOCKED (HTTP 403)<br><br>'+d.message;}"
            + "else{box.className='res res-warn';box.innerHTML='SERVER RESPONSE: '+d.message+'<br>Logged IP: <b>'+d.ip+'</b> | Severity: <b>'+d.severity+'</b>';}"
            + "}catch(e){box.className='res res-blk';box.textContent='Could not reach server. Check Hotspot/Wi-Fi connection.';}}"
            + "</script></body></html>";
    }
}