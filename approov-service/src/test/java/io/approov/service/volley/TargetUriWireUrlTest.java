package io.approov.service.volley;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Target URI Is The Wire URL: the {@code @target-uri} in the signature base is the URL string the stack sends,
 * with no fragment and no explicit default port. A URL that java.net.URI rejects is still signed.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class TargetUriWireUrlTest {
    private MockedStatic<Approov> approov;

    @Before
    public void setUp() {
        ApproovTestSupport.resetApproovServiceState();
        approov = Mockito.mockStatic(Approov.class);
        ApproovTestSupport.initializeApproovService(approov);
        MessageSigningSupport.sdkSignsWithBoth(approov);
    }

    @After
    public void tearDown() {
        approov.close();
        ApproovTestSupport.resetApproovServiceState();
    }

    // signs a request to the URL with both signatures and returns the signature bases the SDK was asked to sign
    private List<String> signatureBases(String url) throws Exception {
        approov.clearInvocations();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "t");
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        Map<String, String> signed = ApproovDefaultMessageSigning.combined().handleRequestProcessedHeaders(
                ApproovTestSupport.request(Request.Method.GET, url, headers, null, null), headers, changes);
        assertNotNull("the request is signed: " + url, signed.get("Signature"));
        ArgumentCaptor<String> bases = ArgumentCaptor.forClass(String.class);
        approov.verify(() -> Approov.getInstallMessageSignature(bases.capture()));
        approov.verify(() -> Approov.getAccountMessageSignature(ArgumentMatchers.anyString()));
        return bases.getAllValues();
    }

    private void assertSignedTargetUri(String expected, String url) throws Exception {
        String base = signatureBases(url).get(0);
        String line = "\"@target-uri\": " + expected + "\n";
        assertTrue("target URI " + expected + " in\n" + base, base.contains(line));
    }

    @Test
    public void theTargetUriIsTheWireUrlForPipeSpacePercentAndEncodedNonAscii() throws Exception {
        String url = "https://api.example.com/search?a=x|y&b=p%20q&c=100%25&d=caf%C3%A9";
        assertSignedTargetUri(url, url);
    }

    @Test
    public void aUrlJavaNetUriRejectsIsStillSigned() throws Exception {
        String url = "https://api.example.com/s?f={%22a%22:1}&c=^`&p=x|y";
        assertSignedTargetUri(url, url);
    }

    @Test
    public void aDefaultPortAndAFragmentAreNotSigned() throws Exception {
        assertSignedTargetUri("https://host/p?a=1", "https://host:443/p?a=1");
        assertSignedTargetUri("http://host/p", "http://host:80/p");
        assertSignedTargetUri("https://host:8443/p", "https://host:8443/p");
        assertSignedTargetUri("http://host:443/p", "http://host:443/p");
        assertSignedTargetUri("https://host/p%2Fx?q=a%20b", "https://host/p%2Fx?q=a%20b#f");
    }

    @Test
    public void theAuthorityIsSignedWithANonDefaultPortOnly() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory(
                        new io.approov.util.volley.sig.SignatureParameters()
                                .addComponentIdentifier(io.approov.util.volley.sig.ComponentProvider.DC_AUTHORITY));
        for (String[] pair : new String[][]{
                {"example.com", "https://Example.com:443/p"},
                {"example.com:8443", "https://example.com:8443/p"}}) {
            approov.clearInvocations();
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Approov-Token", "t");
            ApproovRequestMutations changes = new ApproovRequestMutations();
            changes.setTokenHeaderKey("Approov-Token");
            new ApproovDefaultMessageSigning().setDefaultFactory(factory).handleRequestProcessedHeaders(
                    ApproovTestSupport.request(Request.Method.GET, pair[1], headers, null, null), headers, changes);
            ArgumentCaptor<String> base = ArgumentCaptor.forClass(String.class);
            approov.verify(() -> Approov.getInstallMessageSignature(base.capture()));
            assertTrue(base.getValue(), base.getValue().contains("\"@authority\": " + pair[0] + "\n"));
        }
    }
}
