//
// MIT License
//
// Copyright (c) 2016-present, Approov Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
// ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package io.approov.service.volley;

import android.util.Base64;

import com.criticalblue.approovsdk.Approov;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * Performs pinning for use with HttpsUrlConnection. This implementation of HostnameVerifier is
 * intended to enhance the HostnameVerifier your TLS implementation normally uses. The
 * HostnameVerifier passed into the constructor continues to be executed when verify is called, and
 * the pinning is only applied if it first passes (so this implementation can only be more secure).
 * This pins to the SHA256 of the public key hash of any certificate in the trust chain for the host
 * (so technically this is public key rather than certificate pinning). The pins of the host are
 * looked up without regard to case and ignoring one trailing dot, on both the host and the keys of
 * the pin set. Note that this uses the current live Approov pins so is immediately updated if there
 * is a configuration update to the app.
 * <p>
 * A HostnameVerifier can only reject a host, so a verifier is made for each connection and records
 * why it rejected one, which the stack reports as an SSLPeerUnverifiedException.
 */
final class PinningHostnameVerifier implements HostnameVerifier {
    // logging tag
    private static final String TAG = "ApproovPinVerifier";

    // the hosts already warned of as listed with no pins while the managed trust roots are empty or absent,
    // which is per process as a verifier is made per connection
    private static final Set<String> warnedOsTrustOnlyHosts = new HashSet<>();

    // HostnameVerifier you would normally be using
    private final HostnameVerifier delegate;

    // the pinning failure of this connection, or null if the pins did not reject it
    private volatile SSLPeerUnverifiedException failure;

    /**
     * Construct a PinningHostnameVerifier which delegates
     * the initial verify to a user defined HostnameVerifier before
     * applying pinning on top.
     *
     * @param delegate is the HostnameVerifier to apply before the custom pinning
     */
    public PinningHostnameVerifier(HostnameVerifier delegate) {
        this.delegate = delegate;
    }

    /**
     * Gets the pinning failure of the connection, if the Approov pins rejected it or could not be read.
     *
     * @return the platform pinning exception to report, or null if the pins did not reject the connection
     */
    SSLPeerUnverifiedException failure() {
        return failure;
    }

    /**
     * Forgets the hosts already warned of. This should only be used for testing.
     */
    static void resetWarnings() {
        synchronized (warnedOsTrustOnlyHosts) {
            warnedOsTrustOnlyHosts.clear();
        }
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // check the delegate function first and only proceed if it passes
        if (!delegate.verify(hostname, session))
            return false;

        // before initialization and in bypass mode no Approov pinning is applied, only OS trust
        if (!ApproovService.isApproovProtectionEnabled())
            return true;

        // the pins are looked up for the normalized host, so that neither a pin key nor a host spelled with a
        // different case or a trailing dot escapes the pins
        String host = ApproovService.normalizeHost(hostname);

        // a pin set that cannot be read fails the connection closed
        Map<String, List<String>> allPins;
        Set<String> hostPins;
        try {
            allPins = Approov.getPins("public-key-sha256");
            if (allPins == null)
                throw new IllegalStateException("getPins returned no pins");
            hostPins = pinsFor(host, allPins);
        } catch (RuntimeException e) {
            ApproovLog.e(TAG, "Approov pinning: pins unavailable for " + host + ": " + e);
            SSLPeerUnverifiedException unavailable = new SSLPeerUnverifiedException(
                    "Approov pinning: pins unavailable for " + host);
            unavailable.initCause(e);
            failure = unavailable;
            return false;
        }

        // with no pins the host is validated by OS trust only, which the delegate has checked
        if (hostPins.isEmpty()) {
            if (isListed(host, allPins))
                warnOsTrustOnly(host);
            return true;
        }

        // check to see if any of the pins are in the certificate chain
        try {
            for (Certificate cert : session.getPeerCertificates()) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    String hash = sha256Base64(x509Cert.getPublicKey().getEncoded());
                    if (hostPins.contains(hash))
                        return true;
                }
            }
        } catch (SSLPeerUnverifiedException | RuntimeException e) {
            // a peer whose certificates cannot be read matches no pin
            ApproovLog.d(TAG, "Peer certificates of " + host + " not read: " + e);
        }

        // the connection is rejected, naming the host and never a pin
        ApproovLog.e(TAG, "Approov pinning: no pin matches for " + host);
        failure = new SSLPeerUnverifiedException("Approov pinning: no pin matches for " + host);
        return false;
    }

    /**
     * Gets the pins for a host from the SDK pin set. Each domain that normalizes to the host gives its pins or,
     * if it has none, the managed trust roots (the "*" pin set) if present. The "*" key is never a pattern and
     * never applies to a host that is not listed, and no domain applies to another host, such as a subdomain.
     *
     * @param host is the normalized host
     * @param allPins is the SDK pin set
     * @return the pins for the host, which are empty if the host is not listed or has no pins and no managed
     * trust roots
     * @throws IllegalStateException if the pin set lists a domain without a pin list
     */
    static Set<String> pinsFor(String host, Map<String, List<String>> allPins) {
        List<String> managedTrustRoots = allPins.get("*");
        Set<String> hostPins = new HashSet<>();
        for (Map.Entry<String, List<String>> entry : allPins.entrySet()) {
            String domain = entry.getKey();
            if ("*".equals(domain))
                continue;
            if ((domain == null) || (entry.getValue() == null))
                throw new IllegalStateException("getPins returned a domain without pins");
            if (!ApproovService.normalizeHost(domain).equals(host))
                continue;

            // if there are no pins then we try and use any managed trust roots
            List<String> pins = entry.getValue();
            if (pins.isEmpty() && (managedTrustRoots != null))
                pins = managedTrustRoots;
            for (String pin : pins) {
                if (pin != null)
                    hostPins.add(pin);
            }
        }
        return hostPins;
    }

    /**
     * Determines if a host is listed in the SDK pin set, as a key other than "*" that normalizes to it.
     *
     * @param host is the normalized host
     * @param allPins is the SDK pin set
     * @return true if the host is listed
     */
    private static boolean isListed(String host, Map<String, List<String>> allPins) {
        for (String domain : allPins.keySet()) {
            if ((domain != null) && !domain.equals("*") && ApproovService.normalizeHost(domain).equals(host))
                return true;
        }
        return false;
    }

    /**
     * Warns once per host that an Approov domain with no pins of its own is validated by OS trust only,
     * because the managed trust roots are empty or absent. This is a valid development setup, but should
     * not be silent. The host is named, never a pin.
     *
     * @param host is the normalized host
     */
    private static void warnOsTrustOnly(String host) {
        synchronized (warnedOsTrustOnlyHosts) {
            if (!warnedOsTrustOnlyHosts.add(host))
                return;
        }
        ApproovLog.w(TAG, "Approov domain " + host + ": no pins and no managed trust roots, OS trust only");
    }

    /**
     * Computes the base64-encoded SHA-256 of the given bytes, matching the Approov
     * "public-key-sha256" pin form. Uses the platform MessageDigest/Base64 so the service layer
     * carries no third-party dependency purely for pin hashing.
     *
     * @param data the bytes to hash (a certificate's encoded public key)
     * @return the base64 (no-wrap) SHA-256 digest
     */
    private static String sha256Base64(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return Base64.encodeToString(digest, Base64.NO_WRAP);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every Android platform; a failure here is fatal.
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
