package com.honeypot.io;

import com.honeypot.model.ThreatEvent;
import java.io.*;
import java.util.Vector;

public class ForensicLogger {
    private final File logDir;
    private final File auditLogFile;
    private final File rawPayloadFile;

    public ForensicLogger(String dirPath) {
        this.logDir = new File(dirPath);
        if (!logDir.exists()) {
            logDir.mkdirs();
        }
        this.auditLogFile = new File(logDir, "intrusion_audit.log");
        this.rawPayloadFile = new File(logDir, "raw_payloads.bin");
    }

    // Unit 4: Synchronized writing via Character Stream & Byte Stream
    public synchronized void logEvent(ThreatEvent event) {
        // 1. Character Stream (FileWriter + BufferedWriter) for readable logs
        try (FileWriter fw = new FileWriter(auditLogFile, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            bw.write(event.formatForAuditLog());
            bw.newLine();
        } catch (IOException e) {
            System.err.println("[IO-ERROR] Audit log write failed: " + e.getMessage());
        }

        // 2. Byte Stream (FileOutputStream) for raw binary forensic evidence
        if (event.getRawBytes().length > 0) {
            try (FileOutputStream fos = new FileOutputStream(rawPayloadFile, true)) {
                byte[] header = ("\n--- " + event.getSourceIp() + ":" + event.getTargetPort() + " ---\n").getBytes();
                fos.write(header);
                fos.write(event.getRawBytes());
            } catch (IOException e) {
                System.err.println("[IO-ERROR] Raw payload capture failed: " + e.getMessage());
            }
        }
    }

    // Unit 1: Method Overloading (logging system lifecycle messages via OutputStreamWriter)
    public synchronized void logEvent(String systemNote) {
        try (OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(auditLogFile, true))) {
            osw.write("[SYSTEM] " + systemNote + System.lineSeparator());
        } catch (IOException e) {
            System.err.println("[IO-ERROR] System note write failed: " + e.getMessage());
        }
    }

    // Unit 4 & 5: FileReader + BufferedReader loading into thread-safe Vector
    public Vector<String> loadBlacklist(String filePath) {
        Vector<String> list = new Vector<>();
        File file = new File(filePath);
        if (!file.exists()) {
            return list;
        }
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    list.add(trimmed);
                }
            }
        } catch (IOException e) {
            System.err.println("[IO-ERROR] Could not read blacklist: " + e.getMessage());
        }
        return list;
    }

    // Unit 4: Byte Stream reading via FileInputStream
    public int countRawPayloadBytes() {
        if (!rawPayloadFile.exists()) return 0;
        int total = 0;
        try (FileInputStream fis = new FileInputStream(rawPayloadFile)) {
            while (fis.read() != -1) {
                total++;
            }
        } catch (IOException e) {
            System.err.println("[IO-ERROR] Raw read error: " + e.getMessage());
        }
        return total;
    }

    // Unit 1: Recursion + Unit 4: File class
    public long calculateLogFolderSize(File folder) {
        long size = 0;
        File[] files = folder.listFiles();
        if (files == null) return 0;
        for (File f : files) {
            if (f.isFile()) {
                size += f.length();
            } else if (f.isDirectory()) {
                size += calculateLogFolderSize(f); // Recursive traversal
            }
        }
        return size;
    }

    public File getLogDir() {
        return logDir;
    }
}