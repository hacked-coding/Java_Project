package com.honeypot.network;

import com.honeypot.model.AbstractSensor;
import java.net.InetAddress;
import java.net.UnknownHostException;

// Unit 2: Intermediate class forming Multilevel Inheritance
public abstract class NetworkSensor extends AbstractSensor {
    protected final ThreatMonitorQueue threatQueue;
    protected final String serviceBanner;
    protected InetAddress localHostAddress;

    public NetworkSensor(String prefix, int port, String serviceBanner, ThreatMonitorQueue threatQueue) {
        super(prefix, port); // Unit 2: super keyword constructor chaining
        this.serviceBanner = serviceBanner;
        this.threatQueue = threatQueue;
        try {
            this.localHostAddress = InetAddress.getLocalHost(); // Unit 5: InetAddress
        } catch (UnknownHostException e) {
            this.localHostAddress = InetAddress.getLoopbackAddress();
        }
    }

    public String getHostInfo() {
        return localHostAddress.getHostName() + " (" + localHostAddress.getHostAddress() + ")";
    }
}