package com.honeypot.app;

import java.io.*;
import java.net.*;

public class LiveAttackSimulator {
    public static void main(String[] args) throws IOException {
        String targetHost = (args.length > 0) ? args[0] : "127.0.0.1";
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("==========================================");
        System.out.println("   LIVE ATTACK SIMULATOR (DEMO CLIENT)    ");
        System.out.println("   Target Honeypot: " + targetHost);
        System.out.println("==========================================");

        while (true) {
            System.out.println("\nChoose simulated attack to launch:");
            System.out.println("1. Fake SSH Root Login Probe (TCP 2222 - HIGH)");
            System.out.println("2. HTTP SQL Injection Payload (TCP 8080 - HIGH)");
            System.out.println("3. FTP Stealth Port Recon Scan (TCP 2121 - LOW)");
            System.out.println("4. UDP Spoofed Beacon Packet (UDP 9090 - MEDIUM)");
            System.out.println("5. Exit Simulator");
            System.out.print("Select [1-5]: ");

            String choice = reader.readLine();
            if (choice == null || choice.equals("5")) break;

            switch (choice.trim()) {
                case "1":
                    sendTcpAttack(targetHost, 2222, "USER root PASS toor123\r\n");
                    break;
                case "2":
                    sendTcpAttack(targetHost, 8080, "GET /admin?id=1' OR '1'='1'; DROP TABLE users;-- HTTP/1.1\r\n");
                    break;
                case "3":
                    sendTcpAttack(targetHost, 2121, "");
                    break;
                case "4":
                    sendUdpAttack(targetHost, 9090, "UDP_RECON_PROBE:SCAN_SUBNET");
                    break;
                default:
                    System.out.println("Invalid option.");
            }
        }
    }

    private static void sendTcpAttack(String host, int port, String payload) {
        try (Socket socket = new Socket(host, port)) {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String banner = in.readLine();
            System.out.println("[DECOY BANNER RECEIVED] " + banner);

            if (!payload.isEmpty()) {
                OutputStream out = socket.getOutputStream();
                out.write(payload.getBytes());
                out.flush();
                System.out.println("[SENT TCP PAYLOAD] -> " + host + ":" + port);
            } else {
                System.out.println("[SENT TCP PORT SCAN] -> " + host + ":" + port);
            }
        } catch (IOException e) {
            System.out.println("[FAILED] Could not connect to " + host + ":" + port + " (" + e.getMessage() + ")");
        }
    }

    private static void sendUdpAttack(String host, int port, String message) {
        try (DatagramSocket ds = new DatagramSocket()) {
            byte[] data = message.getBytes();
            InetAddress addr = InetAddress.getByName(host);
            DatagramPacket packet = new DatagramPacket(data, data.length, addr, port);
            ds.send(packet);
            System.out.println("[SENT UDP PACKET] -> " + host + ":" + port);
        } catch (IOException e) {
            System.out.println("[FAILED] UDP send failed: " + e.getMessage());
        }
    }
}