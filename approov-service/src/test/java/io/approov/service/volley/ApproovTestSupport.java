package io.approov.service.volley;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.Context;

import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.Response;
import com.criticalblue.approovsdk.Approov;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.mockito.MockedStatic;

final class ApproovTestSupport {

    private ApproovTestSupport() {
    }

    static void resetApproovServiceState() {
        setStaticField("hurlStack", null);
        setStaticField("isInitialized", false);
        setStaticField("configString", null);
        setStaticField("proceedOnNetworkFail", false);
        setStaticField("useApproovStatusIfNoToken", false);
        setStaticField("approovTokenHeader", null);
        setStaticField("approovTokenPrefix", null);
        setStaticField("approovTraceIDHeader", null);
        setStaticField("bindingHeader", null);
        setStaticField("serviceMutator", ApproovServiceMutator.DEFAULT);
        setStaticField("exclusionURLRegexs", new HashMap<String, Pattern>());
    }

    static void initializeApproovService(MockedStatic<Approov> approov) {
        resetApproovServiceState();
        approov.when(() -> Approov.getPins("public-key-sha256")).thenReturn(new HashMap<>());
        Context context = mock(Context.class);
        when(context.getApplicationContext()).thenReturn(context);
        ApproovService.initialize(context, "dummy-config", "reinit-tests");
    }

    static Context mockContext() {
        Context context = mock(Context.class);
        when(context.getApplicationContext()).thenReturn(context);
        return context;
    }

    static Approov.TokenFetchResult tokenResult(Approov.TokenFetchStatus status) {
        return tokenResult(status, "", "", "", false);
    }

    static Approov.TokenFetchResult tokenResult(
            Approov.TokenFetchStatus status,
            String token,
            String secureString,
            String traceID,
            boolean configChanged
    ) {
        Approov.TokenFetchResult result = mock(Approov.TokenFetchResult.class);
        when(result.getStatus()).thenReturn(status);
        when(result.getToken()).thenReturn(token);
        when(result.getSecureString()).thenReturn(secureString);
        when(result.getTraceID()).thenReturn(traceID);
        when(result.getLoggableToken()).thenReturn(token);
        when(result.getARC()).thenReturn("ARC123");
        when(result.getRejectionReasons()).thenReturn("hooked,rooted");
        when(result.isConfigChanged()).thenReturn(configChanged);
        return result;
    }

    static TestRequest request(String url) {
        return new TestRequest(Request.Method.GET, url, new LinkedHashMap<String, String>(), null, null);
    }

    static TestRequest request(
            int method,
            String url,
            Map<String, String> headers,
            byte[] body,
            String bodyContentType
    ) {
        return new TestRequest(method, url, headers, body, bodyContentType);
    }

    @SuppressWarnings("unchecked")
    static <T> T getStaticField(String name, Class<T> type) {
        try {
            Field field = ApproovService.class.getDeclaredField(name);
            field.setAccessible(true);
            return (T) field.get(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to read field " + name, e);
        }
    }

    private static void setStaticField(String name, Object value) {
        try {
            Field field = ApproovService.class.getDeclaredField(name);
            field.setAccessible(true);
            field.set(null, value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to reset field " + name, e);
        }
    }

    static final class TestRequest extends Request<String> {
        private final Map<String, String> headers;
        private final byte[] body;
        private final String bodyContentType;

        TestRequest(int method, String url, Map<String, String> headers, byte[] body, String bodyContentType) {
            super(method, url, null);
            this.headers = headers == null ? new LinkedHashMap<String, String>() : new LinkedHashMap<>(headers);
            this.body = body;
            this.bodyContentType = bodyContentType;
        }

        @Override
        public Map<String, String> getHeaders() {
            return new LinkedHashMap<>(headers);
        }

        @Override
        public byte[] getBody() {
            return body;
        }

        @Override
        public String getBodyContentType() {
            if (bodyContentType != null) {
                return bodyContentType;
            }
            return super.getBodyContentType();
        }

        @Override
        protected Response<String> parseNetworkResponse(NetworkResponse response) {
            return Response.success("ok", null);
        }

        @Override
        protected void deliverResponse(String response) {
        }
    }

    static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
