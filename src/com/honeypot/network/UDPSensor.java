package com.honeypot.network;

import com.honeypot.exception.BlacklistedIPException;
import com.honeypot.model.ThreatEvent;
import java.io.IOException;
import java.net.*;
import java.util.Arrays;

public class UDPSensor extends NetworkSensor implements Runnable {
    private DatagramSocket datagramSocket;

    public UDPSensor(int port, ThreatMonitorQueue threatQueue) {
        super("UDP-SENSOR", port, "UDP-DECOY-LISTENER", threatQueue);
    }

    @Override
    public String getProtocolName() {
        return "UDP";
    }

    @Override
    public void run() {
        try {
            datagramSocket = new DatagramSocket(port);
            active = true;
            tracker.transitionTo("MONITORING");

            byte[] buffer = new byte[1024];
            while (active) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                datagramSocket.receive(packet);

                String remoteIp = packet.getAddress().getHostAddress();
                byte[] payload = Arrays.copyOf(packet.getData(), packet.getLength());
                tracker.transitionTo("UNDER_ATTACK");

                try {
                    threatQueue.verifyIpNotBlacklisted(remoteIp);
                    // Calls overloaded ThreatEvent constructor
                    ThreatEvent event = new ThreatEvent("UDP", remoteIp, port, payload);
                    threatQueue.pushThreat(event);
                } catch (BlacklistedIPException bEx) {
                    tracker.transitionTo("IP_BLOCKED");
                    byte[] combined = (bEx.getMessage() + " | Raw: " + new String(payload)).getBytes();
                    threatQueue.pushThreat(new ThreatEvent("UDP", remoteIp, port, bEx.getSeverity(), combined));
                } finally {
                    if (active) tracker.transitionTo("MONITORING");
                }
            }
        } catch (SocketException se) {
            // Normal exit when stopSensor() closes DatagramSocket
        } catch (IOException e) {
            System.err.println("[" + sensorId + "] UDP error: " + e.getMessage());
        } finally {
            tracker.transitionTo("STOPPED");
        }
    }

    @Override
    public void stopSensor() {
        active = false;
        if (datagramSocket != null && !datagramSocket.isClosed()) {
            datagramSocket.close();
        }
    }
}