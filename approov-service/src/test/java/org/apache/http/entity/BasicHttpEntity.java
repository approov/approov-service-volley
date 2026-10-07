package org.apache.http.entity;

import org.apache.http.Header;
import org.apache.http.HttpEntity;

import java.io.InputStream;

public class BasicHttpEntity implements HttpEntity {
    private InputStream content;
    private long contentLength = -1;
    private Header contentType;
    private Header contentEncoding;

    public void setContent(InputStream content) {
        this.content = content;
    }

    public void setContentLength(long contentLength) {
        this.contentLength = contentLength;
    }

    public void setContentType(Header contentType) {
        this.contentType = contentType;
    }

    public void setContentEncoding(Header contentEncoding) {
        this.contentEncoding = contentEncoding;
    }

    @Override
    public InputStream getContent() {
        return content;
    }

    @Override
    public long getContentLength() {
        return contentLength;
    }

    @Override
    public Header getContentType() {
        return contentType;
    }

    @Override
    public Header getContentEncoding() {
        return contentEncoding;
    }
}
