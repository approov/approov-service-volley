package org.apache.http;

public class ProtocolVersion {
    private final String protocol;
    private final int major;
    private final int minor;

    public ProtocolVersion(String protocol, int major, int minor) {
        this.protocol = protocol;
        this.major = major;
        this.minor = minor;
    }

    public String getProtocol() {
        return protocol;
    }

    public int getMajor() {
        return major;
    }

    public int getMinor() {
        return minor;
    }
}
