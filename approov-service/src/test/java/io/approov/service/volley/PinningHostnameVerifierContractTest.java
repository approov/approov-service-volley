package io.approov.service.volley;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * Exercises the pin checking performed by PinningHostnameVerifier.verify() directly
 * against fake SSL sessions, covering acceptance, rejection on pin mismatch, the
 * unpinned host case and the managed trust roots wildcard fallback.
 */
public class PinningHostnameVerifierContractTest {
    private static final String HOST = "api.example.com";

    private MockedStatic<Approov> approovMock;
    private HostnameVerifier delegate;

    @Before
    public void setUp() {
        approovMock = Mockito.mockStatic(Approov.class);
        delegate = mock(HostnameVerifier.class);
        when(delegate.verify(anyString(), Mockito.any())).thenReturn(true);
    }

    @After
    public void tearDown() {
        approovMock.close();
    }

    private static String pinOf(byte[] encodedPublicKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(encodedPublicKey);
        return java.util.Base64.getEncoder().encodeToString(digest);
    }

    private static SSLSession sessionWithPublicKey(byte[] encodedPublicKey) throws Exception {
        PublicKey publicKey = mock(PublicKey.class);
        when(publicKey.getEncoded()).thenReturn(encodedPublicKey);
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getPublicKey()).thenReturn(publicKey);
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
        return session;
    }

    private void givenPins(Map<String, List<String>> pins) {
        approovMock.when(() -> Approov.getPins("public-key-sha256")).thenReturn(pins);
    }

    @Test
    public void acceptsConnectionWhenPinMatches() throws Exception {
        byte[] keyBytes = "server-public-key".getBytes(StandardCharsets.UTF_8);
        givenPins(Collections.singletonMap(HOST, Collections.singletonList(pinOf(keyBytes))));

        PinningHostnameVerifier verifier = new PinningHostnameVerifier(delegate);
        assertTrue(verifier.verify(HOST, sessionWithPublicKey(keyBytes)));
    }

    @Test
    public void rejectsConnectionOnPinMismatch() throws Exception {
        byte[] pinnedKey = "expected-public-key".getBytes(StandardCharsets.UTF_8);
        byte[] presentedKey = "attacker-public-key".getBytes(StandardCharsets.UTF_8);
        givenPins(Collections.singletonMap(HOST, Collections.singletonList(pinOf(pinnedKey))));

        PinningHostnameVerifier verifier = new PinningHostnameVerifier(delegate);
        assertFalse(verifier.verify(HOST, sessionWithPublicKey(presentedKey)));
    }

    @Test
    public void acceptsConnectionForHostWithoutPins() throws Exception {
        givenPins(Collections.singletonMap("other.example.com",
                Collections.singletonList(pinOf("unrelated".getBytes(StandardCharsets.UTF_8)))));

        PinningHostnameVerifier verifier = new PinningHostnameVerifier(delegate);
        SSLSession session = sessionWithPublicKey("any-key".getBytes(StandardCharsets.UTF_8));
        assertTrue(verifier.verify(HOST, session));
    }

    @Test
    public void emptyHostPinsFallBackToManagedTrustRoots() throws Exception {
        byte[] keyBytes = "managed-roots-key".getBytes(StandardCharsets.UTF_8);
        Map<String, List<String>> pins = new HashMap<>();
        pins.put(HOST, Collections.<String>emptyList());
        pins.put("*", Collections.singletonList(pinOf(keyBytes)));
        givenPins(pins);

        PinningHostnameVerifier verifier = new PinningHostnameVerifier(delegate);
        assertTrue(verifier.verify(HOST, sessionWithPublicKey(keyBytes)));
        assertFalse(verifier.verify(HOST,
                sessionWithPublicKey("other-key".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void rejectsConnectionWhenDelegateRejects() throws Exception {
        when(delegate.verify(anyString(), Mockito.any())).thenReturn(false);
        byte[] keyBytes = "server-public-key".getBytes(StandardCharsets.UTF_8);
        givenPins(Collections.singletonMap(HOST, Collections.singletonList(pinOf(keyBytes))));

        PinningHostnameVerifier verifier = new PinningHostnameVerifier(delegate);
        SSLSession session = sessionWithPublicKey(keyBytes);
        assertFalse(verifier.verify(HOST, session));
        verify(session, never()).getPeerCertificates();
    }
}
