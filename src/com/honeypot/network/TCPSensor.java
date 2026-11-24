package com.honeypot.network;

import com.honeypot.exception.BlacklistedIPException;
import com.honeypot.model.ThreatEvent;
import java.io.*;
import java.net.*;
import java.util.Arrays;

public class TCPSensor extends NetworkSensor implements Runnable {
    private ServerSocket serverSocket;

    public TCPSensor(int port, String serviceBanner, ThreatMonitorQueue threatQueue) {
        super("TCP-SENSOR", port, serviceBanner, threatQueue);
    }

    @Override
    public String getProtocolName() {
        return "TCP";
    }

    @Override
    public void run() {
        try {
            serverSocket = new ServerSocket(port);
            active = true;
            tracker.transitionTo("MONITORING");

            while (active) {
                Socket client = serverSocket.accept();
                handleClient(client);
            }
        } catch (SocketException se) {
            // Normal exit when stopSensor() closes ServerSocket
        } catch (IOException e) {
            System.err.println("[" + sensorId + "] Port " + port + " error: " + e.getMessage());
        } finally {
            tracker.transitionTo("STOPPED");
        }
    }

    private void handleClient(Socket client) {
        String remoteIp = client.getInetAddress().getHostAddress();
        tracker.transitionTo("UNDER_ATTACK");
        try {
            client.setSoTimeout(2500);

            // Send fake decoy service banner
            OutputStreamWriter writer = new OutputStreamWriter(client.getOutputStream());
            writer.write(serviceBanner + "\r\n");
            writer.flush();

            // Capture attacker payload bytes
            InputStream in = client.getInputStream();
            byte[] buffer = new byte[1024];
            int bytesRead = -1;
            try {
                bytesRead = in.read(buffer);
            } catch (SocketTimeoutException ignored) {
                // Stealth port scan with no payload sent
            }

            byte[] payload = (bytesRead > 0) ? Arrays.copyOf(buffer, bytesRead) : new byte[0];

            try {
                threatQueue.verifyIpNotBlacklisted(remoteIp);
                String severity = classifySeverity(new String(payload));
                ThreatEvent event = new ThreatEvent("TCP", remoteIp, port, severity, payload);
                threatQueue.pushThreat(event);
            } catch (BlacklistedIPException bEx) {
                tracker.transitionTo("IP_BLOCKED");
                byte[] combined = (bEx.getMessage() + " | Raw: " + new String(payload)).getBytes();
                threatQueue.pushThreat(new ThreatEvent("TCP", remoteIp, port, bEx.getSeverity(), combined));
            }
        } catch (IOException ignored) {
            // Remote host reset connection
        } finally {
            try {
                client.close();
            } catch (IOException ignored) {}
            if (active) tracker.transitionTo("MONITORING");
        }
    }

    private String classifySeverity(String text) {
        String lower = text.toLowerCase();
        if (lower.contains("root") || lower.contains("admin") || lower.contains("select") || lower.contains("drop")) {
            return "HIGH";
        }
        return text.trim().isEmpty() ? "LOW" : "MEDIUM";
    }

    @Override
    public void stopSensor() {
        active = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException ignored) {}
    }
}