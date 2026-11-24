package com.honeypot.app;

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
        {"8080", "HTTP/1.1 200 OK\r\nServer: Gov-Portal-Admin/2.4\r\n\r\nRestricted Login"},
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

        // Cloud hosts (jaise Render) PORT env variable dete hain; local/Codespaces par 8000 use hoga
        String portEnv = System.getenv("PORT");
        int webPort = (portEnv != null && !portEnv.trim().isEmpty()) ? Integer.parseInt(portEnv.trim()) : 8000;

        String tcpPortsProp = config.getProperty("tcp.ports", "2222,8080,2121");
        int udpPort = Integer.parseInt(config.getProperty("udp.port", "9090"));
        String logDir = config.getProperty("log.dir", "logs");
        String blacklistFile = config.getProperty("blacklist.file", "config/blacklist.txt");

        ForensicLogger logger = new ForensicLogger(logDir);
        Vector<String> blacklist = logger.loadBlacklist(blacklistFile);
        ThreatMonitorQueue threatQueue = new ThreatMonitorQueue(blacklist);

        AlertListener webAlertHandler = new AlertListener() {
            @Override
            public void onThreatDetected(ThreatEvent event) {
                logger.logEvent(event);
                synchronized (recentAlerts) {
                    recentAlerts.add(0, event);
                    if (recentAlerts.size() > 50) {
                        recentAlerts.remove(recentAlerts.size() - 1);
                    }
                }
                System.out.println("[WEB-SOC] " + event.toString());
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
                if (port == webPort) continue; // Web dashboard port se clash avoid karne ke liye
                TCPSensor tcpSensor = new TCPSensor(port, lookupBanner(port), threatQueue);
                sensors.add(tcpSensor);
                new Thread(tcpSensor, "Thread-TCP-" + port).start();
            } catch (NumberFormatException ignored) {}
        }

        UDPSensor udpSensor = new UDPSensor(udpPort, threatQueue);
        sensors.add(udpSensor);
        new Thread(udpSensor, "Thread-UDP-" + udpPort).start();

        logger.logEvent("Web SOC Dashboard started on port " + webPort);

        // Built-in Core Java HTTP Server
        HttpServer server = HttpServer.create(new InetSocketAddress(webPort), 0);

        // 1. Main Website Dashboard HTML
        server.createContext("/", exchange -> {
            byte[] html = buildDashboardHtml().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, html.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(html);
            }
        });

        // 2. Live State JSON API (Sensors, Alerts, Blacklist, Forensic Stats)
        server.createContext("/api/state", exchange -> {
            String json = buildStateJson(sensors, threatQueue, logger);
            sendJson(exchange, 200, json);
        });

        // 3. One-Click Live Attack Trigger API (Real TCP/UDP loopback sockets)
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

        // 4. Live IP Blacklist API
        server.createContext("/api/block", exchange -> {
            String ip = getQueryParam(exchange.getRequestURI().getQuery(), "ip");
            if (ip != null && !ip.trim().isEmpty()) {
                threatQueue.addToBlacklist(ip.trim());
                logger.logEvent("Web operator blacklisted IP: " + ip.trim());
                sendJson(exchange, 200, "{\"status\":\"blocked\",\"ip\":\"" + escapeJson(ip.trim()) + "\"}");
            } else {
                sendJson(exchange, 400, "{\"error\":\"IP required\"}");
            }
        });

        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();

        System.out.println("============================================================");
        System.out.println("  LIVE WEB SOC DASHBOARD RUNNING AT: http://localhost:" + webPort);
        System.out.println("============================================================");
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

    private static String buildStateJson(List<AbstractSensor> sensors, ThreatMonitorQueue queue, ForensicLogger logger) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
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

    private static String buildDashboardHtml() {
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            + "<title>Cyber Honeypot & Live IDS - SOC Dashboard</title>"
            + "<style>"
            + "body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:#0b1120;color:#e2e8f0;padding:20px;}"
            + ".wrap{max-width:1100px;margin:auto;}"
            + "h1{margin:0 0 6px;color:#38bdf8;font-size:24px;}"
            + ".sub{color:#94a3b8;margin-bottom:20px;font-size:14px;}"
            + ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:18px;}"
            + ".card{background:#111827;border:1px solid #1e293b;border-radius:10px;padding:16px;}"
            + ".card h3{margin:0 0 10px;font-size:14px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;}"
            + ".stat{font-size:24px;font-weight:700;color:#f8fafc;}"
            + ".btns{display:flex;flex-wrap:wrap;gap:10px;}"
            + "button{border:none;border-radius:8px;padding:10px 14px;font-weight:600;cursor:pointer;color:#fff;font-size:13px;}"
            + ".b-red{background:#dc2626;}.b-amber{background:#d97706;}.b-blue{background:#2563eb;}.b-purple{background:#7c3aed;}.b-slate{background:#334155;}"
            + "button:hover{opacity:.9;}"
            + "input{background:#0f172a;border:1px solid #334155;color:#fff;padding:10px;border-radius:8px;width:190px;}"
            + ".badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700;margin-right:8px;}"
            + ".CRITICAL{background:#7f1d1d;color:#fecaca;}.HIGH{background:#991b1b;color:#fca5a5;}"
            + ".MEDIUM{background:#78350f;color:#fde68a;}.LOW{background:#1e3a8a;color:#bfdbfe;}"
            + ".log-box{background:#020617;border:1px solid #1e293b;border-radius:8px;padding:12px;max-height:360px;overflow-y:auto;font-family:Consolas,monospace;font-size:13px;}"
            + ".log-row{padding:8px;border-bottom:1px solid #0f172a;}"
            + ".pill{display:inline-block;background:#1e293b;padding:4px 10px;border-radius:99px;font-size:12px;margin:4px 6px 0 0;color:#38bdf8;}"
            + "</style></head><body><div class='wrap'>"
            + "<h1>Multi-Threaded Cyber Honeypot &amp; Live IDS</h1>"
            + "<div class='sub'>Pure Core Java SE (TCP/UDP Sockets + Multithreading + Forensic Streams + Built-in HttpServer)</div>"
            + "<div class='grid'>"
            + "<div class='card'><h3>Active Sensors</h3><div class='stat' id='sCount'>0</div></div>"
            + "<div class='card'><h3>Captured Alerts</h3><div class='stat' id='aCount'>0</div></div>"
            + "<div class='card'><h3>Forensic Log Size</h3><div class='stat' id='logSize'>0 B</div></div>"
            + "<div class='card'><h3>Raw Binary Dump</h3><div class='stat' id='rawSize'>0 B</div></div>"
            + "</div>"
            + "<div class='card' style='margin-bottom:18px;'><h3>Live Attack Simulator (Fires Real Sockets to Decoy Ports)</h3>"
            + "<div class='btns'>"
            + "<button class='b-red' onclick=\"triggerAttack('ssh')\">SSH Root Probe (TCP 2222)</button>"
            + "<button class='b-red' onclick=\"triggerAttack('sqli')\">HTTP SQL Injection (TCP 8080)</button>"
            + "<button class='b-blue' onclick=\"triggerAttack('ftp')\">FTP Stealth Scan (TCP 2121)</button>"
            + "<button class='b-purple' onclick=\"triggerAttack('udp')\">UDP Recon Packet (UDP 9090)</button>"
            + "</div></div>"
            + "<div class='grid'>"
            + "<div class='card'><h3>Decoy Sensor Threads</h3><div id='sensors'>Loading...</div></div>"
            + "<div class='card'><h3>Live IP Blacklist (Vector)</h3>"
            + "<div style='display:flex;gap:8px;margin-bottom:10px;'><input id='ipInput' value='127.0.0.1' placeholder='Enter IP'/>"
            + "<button class='b-amber' onclick='blockIp()'>Block IP</button></div>"
            + "<div id='blacklist'></div></div></div>"
            + "<div class='card'><h3>Live Intrusion Feed (Auto-Refreshing)</h3><div class='log-box' id='alerts'>No intrusions detected yet. Click an attack button above to test live.</div></div>"
            + "</div><script>"
            + "function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}"
            + "async function triggerAttack(t){await fetch('/api/attack?type='+t);setTimeout(loadState,450);}"
            + "async function blockIp(){const ip=document.getElementById('ipInput').value.trim();if(!ip)return;await fetch('/api/block?ip='+encodeURIComponent(ip));loadState();}"
            + "async function loadState(){try{const r=await fetch('/api/state');const d=await r.json();"
            + "document.getElementById('sCount').textContent=d.totalSensors;"
            + "document.getElementById('aCount').textContent=d.alerts.length;"
            + "document.getElementById('logSize').textContent=d.logFolderBytes+' B';"
            + "document.getElementById('rawSize').textContent=d.rawPayloadBytes+' B';"
            + "document.getElementById('sensors').innerHTML=d.sensors.map(s=>'<div class=\"pill\">'+esc(s.state)+' ('+esc(s.protocol)+':'+s.port+')</div>').join('');"
            + "document.getElementById('blacklist').innerHTML=d.blacklist.map(ip=>'<span class=\"pill\" style=\"color:#fca5a5\">'+esc(ip)+'</span>').join('');"
            + "if(d.alerts.length){document.getElementById('alerts').innerHTML=d.alerts.map(a=>'<div class=\"log-row\"><span class=\"badge '+esc(a.severity)+'\">'+esc(a.severity)+'</span>'+esc(a.log)+'</div>').join('');}"
            + "}catch(e){}}"
            + "loadState();setInterval(loadState,1500);"
            + "</script></body></html>";
    }
}