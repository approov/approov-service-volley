package org.apache.http;

public interface HttpResponse {
    StatusLine getStatusLine();

    void setEntity(HttpEntity entity);

    HttpEntity getEntity();

    void addHeader(Header header);

    Header[] getAllHeaders();
}
