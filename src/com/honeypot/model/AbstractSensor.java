package com.honeypot.model;

public abstract class AbstractSensor {
    protected final String sensorId;
    protected final int port;
    protected volatile boolean active;
    protected String state;
    protected static int totalSensorsCreated = 0;

    // Unit 1: Static Nested Class
    public static class SensorStats {
        public static int getTotalSensors() {
            return totalSensorsCreated;
        }
    }

    // Unit 1: Non-static Inner Class (tracks Unit 6 State Model)
    public class StateTracker {
        public void transitionTo(String newState) {
            state = newState;
        }

        public String getCurrentState() {
            return sensorId + " [" + state + "]";
        }
    }

    protected final StateTracker tracker = new StateTracker();

    public AbstractSensor(String prefix, int port) {
        totalSensorsCreated++;
        this.sensorId = prefix + "-" + totalSensorsCreated;
        this.port = port;
        this.active = false;
        this.state = "IDLE";
    }

    // Unit 2: final method prevents overriding
    public final String getSensorId() {
        return sensorId;
    }

    public int getPort() {
        return port;
    }

    public String getStateSummary() {
        return tracker.getCurrentState();
    }

    public abstract String getProtocolName();
    public abstract void stopSensor();
}