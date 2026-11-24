package com.honeypot.app;

import static java.lang.System.out; // Unit 3: Static Import

import com.honeypot.io.ForensicLogger;
import com.honeypot.model.AbstractSensor;
import com.honeypot.model.AlertListener;
import com.honeypot.model.ThreatEvent;
import com.honeypot.network.*;
import java.io.*;
import java.util.*;

public class HoneypotServerApp {
    // Unit 1: Multidimensional Array for decoy port banners
    private static final String[][] DECOY_BANNERS = {
        {"2222", "SSH-2.0-OpenSSH_8.9p1 Gov-Gateway"},
        {"8080", "HTTP/1.1 200 OK\r\nServer: Gov-Portal-Admin/2.4\r\n\r\nRestricted Login"},
        {"2121", "220 Gov-FTP Evidence Archive Server Ready"}
    };

    private static String lookupBanner(int port) {
        for (String[] row : DECOY_BANNERS) {
            if (Integer.parseInt(row[0]) == port) {
                return row[1];
            }
        }
        return "220 Generic Decoy Honeypot Service";
    }

    public static void main(String[] args) {
        Properties config = new Properties(); // Unit 5: Properties
        String configPath = (args.length > 0) ? args[0] : "config/honeypot.properties"; // Unit 1: CLI args

        try (FileInputStream fis = new FileInputStream(configPath)) {
            config.load(fis);
        } catch (IOException e) {
            out.println("[WARN] Config not found at " + configPath + ". Using built-in defaults.");
        }

        String tcpPortsProp = config.getProperty("tcp.ports", "2222,8080,2121");
        int udpPort = Integer.parseInt(config.getProperty("udp.port", "9090"));
        String logDir = config.getProperty("log.dir", "logs");
        String blacklistFile = config.getProperty("blacklist.file", "config/blacklist.txt");

        ForensicLogger logger = new ForensicLogger(logDir);
        Vector<String> blacklist = logger.loadBlacklist(blacklistFile);
        ThreatMonitorQueue threatQueue = new ThreatMonitorQueue(blacklist);

        // Unit 1 & 2: Anonymous Inner Class implementing AlertListener
        AlertListener alertHandler = new AlertListener() {
            private int alertCount = 0;

            @Override
            public void onThreatDetected(ThreatEvent event) {
                alertCount++;
                logger.logEvent(event);
                out.println("\n================ [INTRUSION ALERT #" + alertCount + "] ================");
                out.println(event.toString());
                out.println("============================================================");
                out.print("SOC-CMD> ");
            }

            @Override
            public String formatForAuditLog() {
                return "AlertHandler (Processed: " + alertCount + ")";
            }
        };

        AlertDispatcherThread dispatcher = new AlertDispatcherThread(threatQueue, alertHandler);
        dispatcher.start();

        // Unit 5: ArrayList + Unit 2: Dynamic Method Dispatch via AbstractSensor references
        List<AbstractSensor> sensors = new ArrayList<>();
        String[] portTokens = tcpPortsProp.split(",");

        for (String token : portTokens) {
            try {
                int port = Integer.parseInt(token.trim());
                TCPSensor tcpSensor = new TCPSensor(port, lookupBanner(port), threatQueue);
                sensors.add(tcpSensor);
                new Thread(tcpSensor, "Thread-TCP-" + port).start();
            } catch (NumberFormatException nfe) {
                out.println("[ERROR] Invalid TCP port ignored: " + token);
            }
        }

        UDPSensor udpSensor = new UDPSensor(udpPort, threatQueue);
        sensors.add(udpSensor);
        new Thread(udpSensor, "Thread-UDP-" + udpPort).start();

        logger.logEvent("Honeypot IDS started with " + AbstractSensor.SensorStats.getTotalSensors() + " sensors.");

        out.println("============================================================");
        out.println("   MULTI-THREADED CYBER HONEYPOT & LIVE INTRUSION DETECTOR  ");
        out.println("============================================================");
        out.println("Active Decoy TCP Ports : " + tcpPortsProp);
        out.println("Active Decoy UDP Port  : " + udpPort);
        out.println("Commands: status | block <ip> | stats | exit");
        out.println("------------------------------------------------------------");

        // Unit 4: Console reading via InputStreamReader + BufferedReader
        try (BufferedReader console = new BufferedReader(new InputStreamReader(System.in))) {
            while (true) {
                out.print("SOC-CMD> ");
                String input = console.readLine();
                if (input == null) break;
                String[] parts = input.trim().split("\\s+");
                if (parts[0].isEmpty()) continue;

                switch (parts[0].toLowerCase()) {
                    case "status":
                        for (AbstractSensor s : sensors) {
                            // Unit 2: instanceof operator + Dynamic Method Dispatch
                            String transport = (s instanceof TCPSensor) ? "[Stream/TCP]" : "[Datagram/UDP]";
                            out.println(" -> " + s.getStateSummary() + " | Protocol=" + s.getProtocolName()
                                    + " " + transport + " | Port=" + s.getPort());
                        }
                        break;

                    case "block":
                        if (parts.length < 2) {
                            out.println("Usage: block <ip_address> (e.g., block 127.0.0.1)");
                        } else {
                            threatQueue.addToBlacklist(parts[1]);
                            logger.logEvent("Operator blacklisted IP: " + parts[1]);
                            out.println("[OK] IP added to live blacklist: " + parts[1]);
                        }
                        break;

                    case "stats":
                        out.println("Total Sensors Initialized : " + AbstractSensor.SensorStats.getTotalSensors());
                        out.println("Forensic Log Dir Size     : " + logger.calculateLogFolderSize(logger.getLogDir()) + " bytes");
                        out.println("Raw Captured Payload Size : " + logger.countRawPayloadBytes() + " bytes");
                        out.print("Blacklisted IPs           : ");
                        Enumeration<String> en = threatQueue.getBlacklistedIps().elements();
                        while (en.hasMoreElements()) {
                            out.print(en.nextElement() + " ");
                        }
                        out.println();
                        break;

                    case "exit":
                        out.println("Shutting down sensors and flushing forensic logs...");
                        for (AbstractSensor s : sensors) {
                            s.stopSensor();
                        }
                        threatQueue.shutdown();
                        dispatcher.interrupt();
                        logger.logEvent("Honeypot IDS stopped cleanly.");
                        return;

                    default:
                        out.println("Unknown command. Use: status | block <ip> | stats | exit");
                }
            }
        } catch (IOException e) {
            out.println("[ERROR] Console error: " + e.getMessage());
        }
    }
}