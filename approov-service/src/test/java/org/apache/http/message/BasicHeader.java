package org.apache.http.message;

import org.apache.http.Header;

public class BasicHeader implements Header {
    private final String name;
    private final String value;

    public BasicHeader(String name, String value) {
        this.name = name;
        this.value = value;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }
}
