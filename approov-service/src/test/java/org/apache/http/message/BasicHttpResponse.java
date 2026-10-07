package org.apache.http.message;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;

import java.util.ArrayList;
import java.util.List;

public class BasicHttpResponse implements HttpResponse {
    private final StatusLine statusLine;
    private HttpEntity entity;
    private final List<Header> headers = new ArrayList<>();

    public BasicHttpResponse(StatusLine statusLine) {
        this.statusLine = statusLine;
    }

    @Override
    public StatusLine getStatusLine() {
        return statusLine;
    }

    @Override
    public void setEntity(HttpEntity entity) {
        this.entity = entity;
    }

    @Override
    public HttpEntity getEntity() {
        return entity;
    }

    @Override
    public void addHeader(Header header) {
        headers.add(header);
    }

    @Override
    public Header[] getAllHeaders() {
        return headers.toArray(new Header[0]);
    }
}
