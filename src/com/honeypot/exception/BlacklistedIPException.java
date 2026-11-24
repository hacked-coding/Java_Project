package com.honeypot.exception;

public class BlacklistedIPException extends SecurityAlertException {
    private final String attackerIp;

    public BlacklistedIPException(String attackerIp) {
        super("CRITICAL: Connection blocked from blacklisted IP " + attackerIp, "CRITICAL");
        this.attackerIp = attackerIp;
    }

    public String getAttackerIp() {
        return attackerIp;
    }
}