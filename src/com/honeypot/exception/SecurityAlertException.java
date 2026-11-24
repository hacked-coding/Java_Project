package com.honeypot.exception;

public class SecurityAlertException extends Exception {
    private final String severity;

    public SecurityAlertException(String message, String severity) {
        super(message);
        this.severity = severity;
    }

    public String getSeverity() {
        return severity;
    }
}