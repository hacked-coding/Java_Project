package com.honeypot.network;

import com.honeypot.exception.BlacklistedIPException;
import com.honeypot.model.ThreatEvent;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Vector;

public class ThreatMonitorQueue {
    private final LinkedList<ThreatEvent> queue = new LinkedList<>();
    private final Vector<String> blacklistedIps;
    private volatile boolean running = true;

    public ThreatMonitorQueue(Vector<String> initialBlacklist) {
        this.blacklistedIps = initialBlacklist;
    }

    // Unit 3 & 5: Custom exception check using Vector Enumeration
    public void verifyIpNotBlacklisted(String ip) throws BlacklistedIPException {
        Enumeration<String> elements = blacklistedIps.elements();
        while (elements.hasMoreElements()) {
            if (elements.nextElement().equals(ip)) {
                throw new BlacklistedIPException(ip);
            }
        }
    }

    public void addToBlacklist(String ip) {
        if (!blacklistedIps.contains(ip)) {
            blacklistedIps.add(ip);
        }
    }

    public Vector<String> getBlacklistedIps() {
        return blacklistedIps;
    }

    // Unit 4: Producer method (Thread communication via notifyAll)
    public synchronized void pushThreat(ThreatEvent event) {
        queue.addLast(event);
        notifyAll();
    }

    // Unit 4: Consumer method (Thread communication via wait)
    public synchronized ThreatEvent pullThreat() throws InterruptedException {
        while (queue.isEmpty() && running) {
            wait();
        }
        if (!running && queue.isEmpty()) {
            return null;
        }
        return queue.removeFirst();
    }

    public synchronized void shutdown() {
        running = false;
        notifyAll();
    }
}