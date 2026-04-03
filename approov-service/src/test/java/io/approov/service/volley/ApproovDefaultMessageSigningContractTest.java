package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.android.volley.Request;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;

public class ApproovDefaultMessageSigningContractTest {

    private static final class RecordingSigner extends ApproovDefaultMessageSigning {
        private String installSignatureBase64 = "";
        private String accountSignatureBase64 = "";
        private ApproovException installError;
        private String lastInstallMessage;
        private String lastAccountMessage;

        @Override
        protected String getInstallMessageSignature(String message) throws ApproovException {
            lastInstallMessage = message;
            if (installError != null) {
                throw installError;
            }
            return installSignatureBase64;
        }

        @Override
        protected String getAccountMessageSignature(String message) {
            lastAccountMessage = message;
            return accountSignatureBase64;
        }

        @Override
        protected byte[] decodeBase64(String base64) {
            return Base64.getDecoder().decode(base64);
        }
    }

    private static String derEncodedInstallSignature() {
        byte[] der = new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
        return Base64.getEncoder().encodeToString(der);
    }

    private static ApproovTestSupport.TestRequest signedRequestFixture() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "Bearer jwt-token");
        headers.put("Approov-TraceID", "trace-123");
        headers.put("Authorization", "Bearer auth-token");
        headers.put("Content-Type", "application/json");
        headers.put("Content-Digest", "stale-digest");
        headers.put("Signature", "stale-signature");
        headers.put("Signature-Input", "stale-input");
        headers.put("Signature-Base-Digest", "stale-base-digest");
        return ApproovTestSupport.request(
                Request.Method.POST,
                "https://api.example.com/reply",
                headers,
                ApproovTestSupport.utf8("{\"hello\":\"world\"}"),
                "application/json");
    }

    private static ApproovRequestMutations defaultChanges() {
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        changes.setTraceIDHeaderKey("Approov-TraceID");
        return changes;
    }

    @Test
    public void defaultSigningAddsDigestAndSignatureHeaders() throws Exception {
        RecordingSigner signer = new RecordingSigner();
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        signer.installSignatureBase64 = derEncodedInstallSignature();
        ApproovTestSupport.TestRequest request = signedRequestFixture();
        Map<String, String> signed = signer.handleRequestProcessedHeaders(request, request.getHeaders(), defaultChanges());

        assertTrue(signer.lastInstallMessage.contains("\"@method\""));
        assertTrue(signer.lastInstallMessage.contains("\"@target-uri\""));
        assertTrue(signer.lastInstallMessage.contains("\"approov-token\""));
        assertTrue(signer.lastInstallMessage.contains("\"approov-traceid\""));
        assertTrue(signer.lastInstallMessage.contains("\"content-digest\""));
        assertEquals("Bearer jwt-token", signed.get("Approov-Token"));
        assertEquals("trace-123", signed.get("Approov-TraceID"));
        assertTrue(signed.get("Content-Digest").contains("sha-256=:"));
        assertTrue(signed.get("Signature").contains("install=:"));
        assertTrue(signed.get("Signature-Input").contains("install=("));
        assertFalse(signed.get("Signature").contains("stale-signature"));
        assertFalse(signed.get("Signature-Input").contains("stale-input"));
        assertNull(signed.get("Signature-Base-Digest"));
    }

    @Test
    public void signingTwiceReplacesExistingSignatureAndDigestHeaders() throws Exception {
        RecordingSigner signer = new RecordingSigner();
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        signer.installSignatureBase64 = derEncodedInstallSignature();
        ApproovTestSupport.TestRequest request = signedRequestFixture();

        Map<String, String> signedOnce = signer.handleRequestProcessedHeaders(request, request.getHeaders(), defaultChanges());
        Map<String, String> signedTwice = signer.handleRequestProcessedHeaders(request, signedOnce, defaultChanges());

        assertTrue(signedTwice.get("Content-Digest").contains("sha-256=:"));
        assertTrue(signedTwice.get("Signature").contains("install=:"));
        assertTrue(signedTwice.get("Signature-Input").contains("install=("));
        assertFalse(signedTwice.get("Signature").contains("stale-signature"));
        assertFalse(signedTwice.get("Signature-Input").contains("stale-input"));
        assertNull(signedTwice.get("Signature-Base-Digest"));
    }

    @Test
    public void signingWithoutAnApproovTokenMutationLeavesTheHeadersUnchanged() throws Exception {
        RecordingSigner signer = new RecordingSigner();
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        signer.installSignatureBase64 = derEncodedInstallSignature();
        ApproovTestSupport.TestRequest request = signedRequestFixture();
        Map<String, String> originalHeaders = request.getHeaders();

        Map<String, String> signed = signer.handleRequestProcessedHeaders(
                request,
                originalHeaders,
                new ApproovRequestMutations());

        assertSame(originalHeaders, signed);
        assertEquals("stale-signature", signed.get("Signature"));
        assertEquals("stale-input", signed.get("Signature-Input"));
        assertEquals("stale-digest", signed.get("Content-Digest"));
    }

    @Test
    public void signingSkipsGracefullyWhenInstallSigningIsUnavailable() throws Exception {
        RecordingSigner signer = new RecordingSigner();
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory());
        signer.installError = new ApproovException("no device signature available");
        ApproovTestSupport.TestRequest request = ApproovTestSupport.request(
                Request.Method.POST,
                "https://api.example.com/reply",
                new LinkedHashMap<String, String>() {{
                    put("Approov-Token", "Bearer jwt-token");
                    put("Approov-TraceID", "trace-123");
                    put("Authorization", "Bearer auth-token");
                    put("Content-Type", "application/json");
                }},
                "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8),
                "application/json");

        Map<String, String> signed = signer.handleRequestProcessedHeaders(request, request.getHeaders(), defaultChanges());

        assertNull(signed.get("Content-Digest"));
        assertNull(signed.get("Signature"));
        assertNull(signed.get("Signature-Input"));
        assertNull(signed.get("Signature-Base-Digest"));
    }

    @Test
    public void accountSigningUsesTheAccountSignatureFlow() throws Exception {
        RecordingSigner signer = new RecordingSigner();
        signer.setDefaultFactory(ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                .setUseAccountMessageSigning());
        signer.accountSignatureBase64 = Base64.getEncoder()
                .encodeToString("account-signature".getBytes(StandardCharsets.UTF_8));
        ApproovTestSupport.TestRequest request = signedRequestFixture();

        Map<String, String> signed = signer.handleRequestProcessedHeaders(request, request.getHeaders(), defaultChanges());

        assertTrue(signed.get("Signature").contains("account=:"));
        assertTrue(signed.get("Signature-Input").contains("account=("));
        assertNull(signer.lastInstallMessage);
        assertTrue(signer.lastAccountMessage.contains("\"approov-token\""));
    }
}
