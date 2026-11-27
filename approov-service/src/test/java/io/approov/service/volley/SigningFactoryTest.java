package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The signatures a factory selects: the install signature only by default, the account signature only, or
 * both as the members "install" and "account" of the same headers over the same covered components.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class SigningFactoryTest {
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

    private static Map<String, String> sign(ApproovDefaultMessageSigning.SignatureParametersFactory factory)
            throws Exception {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Approov-Token", "t");
        ApproovRequestMutations changes = new ApproovRequestMutations();
        changes.setTokenHeaderKey("Approov-Token");
        return new ApproovDefaultMessageSigning().setDefaultFactory(factory).handleRequestProcessedHeaders(
                ApproovTestSupport.request(Request.Method.GET, "https://api.example.com/data", headers, null, null),
                headers, changes);
    }

    @Test
    public void aDefaultFactoryProducesTheInstallSignatureOnly() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory();
        assertEquals(Collections.singletonList("ecdsa-p256-sha256"), factory.getAlgs());
        Map<String, String> signed = sign(factory);
        assertTrue(signed.get("Signature"), signed.get("Signature").startsWith("install=:"));
        assertFalse(signed.get("Signature"), signed.get("Signature").contains("account="));
        assertFalse(signed.get("Signature-Input"), signed.get("Signature-Input").contains("account="));
    }

    @Test
    public void aBareFactoryProducesTheInstallSignatureOnly() {
        assertEquals(Collections.singletonList("ecdsa-p256-sha256"),
                new ApproovDefaultMessageSigning.SignatureParametersFactory().getAlgs());
    }

    @Test
    public void theAccountSignatureOnly() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory().setUseAccountMessageSigning();
        assertEquals(Collections.singletonList("hmac-sha256"), factory.getAlgs());
        Map<String, String> signed = sign(factory);
        assertTrue(signed.get("Signature"), signed.get("Signature").startsWith("account=:"));
        assertFalse(signed.get("Signature"), signed.get("Signature").contains("install="));
    }

    @Test
    public void bothSignaturesInOrderOverTheSameComponents() throws Exception {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                ApproovDefaultMessageSigning.generateDefaultSignatureParametersFactory()
                        .setUseInstallAndAccountMessageSigning();
        assertEquals(Arrays.asList("ecdsa-p256-sha256", "hmac-sha256"), factory.getAlgs());
        Map<String, String> signed = sign(factory);
        String signature = signed.get("Signature");
        assertTrue(signature, signature.startsWith("install=:") && signature.contains(", account=:"));
        String input = signed.get("Signature-Input");
        String installComponents = input.substring(input.indexOf("install=("), input.indexOf(")", input.indexOf("install=(")));
        String accountComponents = input.substring(input.indexOf("account=("), input.indexOf(")", input.indexOf("account=(")));
        assertEquals(installComponents.substring("install=(".length()), accountComponents.substring("account=(".length()));
    }

    @Test
    public void theSelectionsReplaceOneAnother() {
        ApproovDefaultMessageSigning.SignatureParametersFactory factory =
                new ApproovDefaultMessageSigning.SignatureParametersFactory()
                        .setUseInstallAndAccountMessageSigning();
        assertEquals(Arrays.asList("ecdsa-p256-sha256", "hmac-sha256"), factory.getAlgs());
        assertEquals(Collections.singletonList("hmac-sha256"), factory.setUseAccountMessageSigning().getAlgs());
        assertEquals(Collections.singletonList("ecdsa-p256-sha256"), factory.setUseInstallMessageSigning().getAlgs());
    }

    @Test
    public void aFactoryWithNoAlgorithmLeavesTheRequestUnsigned() throws Exception {
        // a subclass that selects nothing
        ApproovDefaultMessageSigning.SignatureParametersFactory none =
                new ApproovDefaultMessageSigning.SignatureParametersFactory() {
                    @Override
                    public java.util.List<String> getAlgs() {
                        throw new IllegalStateException("No message signing algorithm is enabled");
                    }
                }.setBaseParameters(new io.approov.util.volley.sig.SignatureParameters()
                        .addComponentIdentifier(io.approov.util.volley.sig.ComponentProvider.DC_METHOD));
        Map<String, String> signed = sign(none);
        assertFalse(signed.containsKey("Signature"));
        assertNotNull(signed.get("Approov-Token"));
        assertThrows(IllegalStateException.class, none::getAlgs);
    }
}
