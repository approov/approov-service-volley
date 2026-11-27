package io.approov.service.volley;

import static org.mockito.ArgumentMatchers.anyString;

import com.criticalblue.approovsdk.Approov;

import org.mockito.MockedStatic;

import java.util.Base64;

/**
 * Signing fixtures: the SDK answers both signatures with fixed values, so no key is needed.
 */
final class MessageSigningSupport {
    // a canonical DER encoding of r=1 and s=2, as the SDK returns the install signature
    static final String INSTALL_SIGNATURE = Base64.getEncoder().encodeToString(
            new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});

    // an HMAC-SHA256 sized value, as the SDK returns the account signature
    static final String ACCOUNT_SIGNATURE = Base64.getEncoder().encodeToString(new byte[32]);

    private MessageSigningSupport() {
    }

    // the SDK answers both signatures
    static void sdkSignsWithBoth(MockedStatic<Approov> approov) {
        approov.when(() -> Approov.getInstallMessageSignature(anyString())).thenReturn(INSTALL_SIGNATURE);
        approov.when(() -> Approov.getAccountMessageSignature(anyString())).thenReturn(ACCOUNT_SIGNATURE);
    }
}
