package com.honeypot.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ThreatEvent implements Loggable {
    private final String timestamp;
    private final String protocol;
    private final String sourceIp;
    private final Integer targetPort; // Unit 1: Wrapper Class
    private final String severity;
    private final String payloadPreview;
    private final byte[] rawBytes;

    // Constructor 1: Explicit severity
    public ThreatEvent(String protocol, String sourceIp, int targetPort, String severity, byte[] rawBytes) {
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.protocol = protocol;
        this.sourceIp = sourceIp;
        this.targetPort = Integer.valueOf(targetPort);
        this.severity = severity;
        this.rawBytes = (rawBytes != null) ? rawBytes : new byte[0];
        this.payloadPreview = new String(this.rawBytes).replaceAll("[\\r\\n]+", " ").trim();
    }

    // Constructor 2: Constructor Overloading (defaults to MEDIUM severity)
    public ThreatEvent(String protocol, String sourceIp, int targetPort, byte[] rawBytes) {
        this(protocol, sourceIp, targetPort, "MEDIUM", rawBytes);
    }

    public String getProtocol() { return protocol; }
    public String getSourceIp() { return sourceIp; }
    public Integer getTargetPort() { return targetPort; }
    public String getSeverity() { return severity; }
    public byte[] getRawBytes() { return rawBytes; }

    public String getPayloadPreview() {
        return payloadPreview.isEmpty() ? "[PORT SCAN / EMPTY PAYLOAD]" : payloadPreview;
    }

    @Override
    public String formatForAuditLog() {
        // Unit 1: StringBuffer for thread-safe log assembly
        StringBuffer sb = new StringBuffer();
        sb.append("[").append(timestamp).append("] ")
          .append("[").append(severity).append("] ")
          .append(protocol).append(" | IP=").append(sourceIp)
          .append(" | PORT=").append(targetPort)
          .append(" | PAYLOAD=").append(getPayloadPreview());
        return sb.toString();
    }

    // Unit 2: Overriding java.lang.Object.toString()
    @Override
    public String toString() {
        return formatForAuditLog();
    }
}