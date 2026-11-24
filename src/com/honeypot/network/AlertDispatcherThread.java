package com.honeypot.network;

import com.honeypot.model.AlertListener;
import com.honeypot.model.ThreatEvent;

// Unit 4: Multithreading via extending Thread class + Thread Priority
public class AlertDispatcherThread extends Thread {
    private final ThreatMonitorQueue queue;
    private final AlertListener listener; // Unit 2: Interface reference

    public AlertDispatcherThread(ThreatMonitorQueue queue, AlertListener listener) {
        super("Alert-Dispatcher-Thread");
        this.queue = queue;
        this.listener = listener;
        this.setPriority(Thread.MAX_PRIORITY);
    }

    @Override
    public void run() {
        try {
            while (!isInterrupted()) {
                ThreatEvent event = queue.pullThreat();
                if (event == null) break;
                listener.onThreatDetected(event);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}