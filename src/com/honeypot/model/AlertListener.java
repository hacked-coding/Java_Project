package com.honeypot.model;

// Unit 2: Interface Inheritance
public interface AlertListener extends Loggable {
    void onThreatDetected(ThreatEvent event);
}