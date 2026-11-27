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

import android.net.Uri;
import android.util.Base64;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.criticalblue.approovsdk.Approov;

import io.approov.util.volley.tink.subtle.EllipticCurves;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import io.approov.util.volley.http.sfv.ByteSequenceItem;
import io.approov.util.volley.http.sfv.Dictionary;
import io.approov.util.volley.http.sfv.ListElement;
import io.approov.util.volley.sig.ComponentProvider;
import io.approov.util.volley.sig.SignatureBaseBuilder;
import io.approov.util.volley.sig.SignatureParameters;

/**
 * Provides a base implementation of HTTP message signing for Volley requests.
 */
public class ApproovDefaultMessageSigning implements ApproovServiceMutator {
    private static final String TAG = "ApproovMsgSign";

    /**
     * Constant for the SHA-256 digest algorithm.
     */
    public static final String DIGEST_SHA256 = "sha-256";

    /**
     * Constant for the SHA-512 digest algorithm.
     */
    public static final String DIGEST_SHA512 = "sha-512";

    /**
     * Constant for the ECDSA P-256 with SHA-256 algorithm.
     */
    public static final String ALG_ES256 = "ecdsa-p256-sha256";

    /**
     * Constant for the HMAC with SHA-256 algorithm.
     */
    public static final String ALG_HS256 = "hmac-sha256";

    /**
     * The Signature dictionary member name for the install message signature.
     */
    public static final String SIG_ID_INSTALL = "install";

    /**
     * The Signature dictionary member name for the account message signature.
     */
    public static final String SIG_ID_ACCOUNT = "account";

    // the factory used for every host without a factory of its own, or null to sign nothing, which is
    // volatile as it is read on the request threads; protected so that subclasses can read and set it
    protected volatile SignatureParametersFactory defaultFactory;

    // factories for individual hosts, keyed by the lowercase host name without any port; protected so that
    // subclasses can read and change them
    protected final Map<String, SignatureParametersFactory> hostFactories = new ConcurrentHashMap<>();

    // true once a missing install signature, a missing account signature, and a request left unsigned for
    // want of any signature have been logged at a visible level, after which they are logged at debug level
    private static final AtomicBoolean installMissingLogged = new AtomicBoolean();
    private static final AtomicBoolean accountMissingLogged = new AtomicBoolean();
    private static final AtomicBoolean unsignedLogged = new AtomicBoolean();

    // clears the once per process flags of the missing signature logs
    static void resetMissingSignatureLogsForTesting() {
        installMissingLogged.set(false);
        accountMissingLogged.set(false);
        unsignedLogged.set(false);
    }

    // the mutator whose decisions the signer makes, or null for the interface default decisions
    private final ApproovServiceMutator decisions;

    /**
     * Constructs a new message signing mutator with no factory, so that nothing is signed until a default
     * factory or a host factory is set. Install it with ApproovService.setServiceMutator.
     */
    public ApproovDefaultMessageSigning() {
        decisions = null;
    }

    /**
     * Constructs a message signing service mutator with no factory that makes the decisions of another
     * mutator, such as ApproovServiceMutator.ALWAYS_PROCEED or your own. Every decision hook calls the hook of
     * that mutator. The processed headers hook calls the processed headers hook of that mutator first and
     * then signs the result, so that the signature covers any change that mutator makes. Nothing is signed
     * until a default factory or a host factory is set. Apps use combined(ApproovServiceMutator) to get a
     * signer.
     *
     * @param decisions is the mutator whose decisions are to be made
     * @throws IllegalArgumentException if decisions is null
     */
    ApproovDefaultMessageSigning(ApproovServiceMutator decisions) {
        if (decisions == null)
            throw new IllegalArgumentException("decisions must not be null");
        this.decisions = decisions;
    }

    /**
     * Gets a new message signing service mutator that adds both the install and the account signature to
     * every request carrying the Approov token header, and makes the decisions of the given mutator, such as
     * ApproovServiceMutator.CLOSE_FAILURE, ApproovServiceMutator.ALWAYS_PROCEED or your own. A signature that
     * cannot be produced is left out and the request goes ahead with the other one, or unsigned. Install it
     * with ApproovService.setServiceMutator.
     *
     * @param decisions is the mutator whose decisions are to be made
     * @return a new signer with the default factory set to sign with both signatures
     * @throws IllegalArgumentException if decisions is null
     */
    public static ApproovDefaultMessageSigning combined(ApproovServiceMutator decisions) {
        return new ApproovDefaultMessageSigning(decisions).setDefaultFactory(
                generateDefaultSignatureParametersFactory().setUseInstallAndAccountMessageSigning());
    }

    /**
     * Gets a new message signing service mutator that adds both the install and the account signature and
     * makes the ApproovServiceMutator.DEFAULT decisions. See combined(ApproovServiceMutator).
     *
     * @return a new signer with the default factory set to sign with both signatures
     */
    public static ApproovDefaultMessageSigning combined() {
        return combined(ApproovServiceMutator.DEFAULT);
    }

    @Override
    public String toString() {
        if (decisions == null)
            return "ApproovDefaultMessageSigning";
        return "ApproovDefaultMessageSigning(" + decisions + ")";
    }

    /**
     * Gets the mutator whose decisions the signer makes.
     *
     * @return the mutator given to the constructor, or CLOSE_FAILURE, whose decisions are the interface
     * defaults, for the signer constructed with no argument
     */
    private ApproovServiceMutator decisions() {
        return (decisions != null) ? decisions : ApproovServiceMutator.CLOSE_FAILURE;
    }

    @Override
    public void handlePrecheckResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        decisions().handlePrecheckResult(approovResults);
    }

    @Override
    public void handleFetchTokenResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        decisions().handleFetchTokenResult(approovResults);
    }

    @Override
    public void handleFetchSecureStringResult(Approov.TokenFetchResult approovResults, String operation, String key)
            throws ApproovException {
        decisions().handleFetchSecureStringResult(approovResults, operation, key);
    }

    @Override
    public void handleFetchCustomJWTResult(Approov.TokenFetchResult approovResults) throws ApproovException {
        decisions().handleFetchCustomJWTResult(approovResults);
    }

    @Override
    public boolean handleRequestShouldProcess(Request<?> request, Map<String, String> additionalHeaders)
            throws ApproovException {
        return decisions().handleRequestShouldProcess(request, additionalHeaders);
    }

    @Override
    public boolean handleRequestFetchTokenResult(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        return decisions().handleRequestFetchTokenResult(approovResults, url);
    }

    @Override
    @Deprecated
    public String handleRequestTokenHeaderValue(Approov.TokenFetchResult approovResults, String url)
            throws ApproovException {
        return decisions().handleRequestTokenHeaderValue(approovResults, url);
    }

    @Override
    public boolean handleRequestHeaderSubstitutionResult(Approov.TokenFetchResult approovResults, String header)
            throws ApproovException {
        return decisions().handleRequestHeaderSubstitutionResult(approovResults, header);
    }

    @Override
    public boolean handleRequestQueryParamSubstitutionResult(Approov.TokenFetchResult approovResults,
            String queryKey) throws ApproovException {
        return decisions().handleRequestQueryParamSubstitutionResult(approovResults, queryKey);
    }

    /**
     * Sets the factory used for every host without a factory of its own.
     *
     * @param factory the factory to set as the default, or null to sign nothing for such hosts
     * @return the current instance for chaining
     */
    public ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory factory) {
        this.defaultFactory = factory;
        return this;
    }

    /**
     * Associates a specific host with a signature parameters factory.
     *
     * @param hostName the host name, matched without regard to case and without any port
     * @param factory the factory to associate with the host, or null to use the default factory again
     * @return the current instance for chaining
     */
    public ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory factory) {
        if (hostName == null)
            throw new IllegalArgumentException("hostName must not be null");
        String key = hostName.toLowerCase(Locale.ROOT);
        if (factory == null)
            hostFactories.remove(key);
        else
            hostFactories.put(key, factory);
        return this;
    }

    /**
     * Selects the factory for a request, which is the factory of its host if there is one or otherwise
     * the default factory.
     *
     * @param provider the component provider for the request
     * @return the factory, or null if none applies
     */
    private SignatureParametersFactory factoryFor(VolleyComponentProvider provider) {
        SignatureParametersFactory factory = hostFactories.get(provider.getHost().toLowerCase(Locale.ROOT));
        return (factory != null) ? factory : defaultFactory;
    }

    /**
     * Builds the signature parameters for a request from the factory for its host, or the default factory.
     * A subclass may override this to choose or adjust the parameters per request.
     *
     * @param provider the component provider for the request
     * @param changes the mutations applied to the request by Approov
     * @return the signature parameters, or null if the request is not to be signed
     * @throws RequiredBodyDigestException if a body digest configured as required cannot be generated, which
     * aborts the request, while any other exception leaves the request unsigned
     */
    protected SignatureParameters buildSignatureParameters(VolleyComponentProvider provider,
            ApproovRequestMutations changes) {
        SignatureParametersFactory factory = factoryFor(provider);
        if (factory == null)
            return null;
        return factory.buildSignatureParameters(provider, changes);
    }

    /**
     * Retrieves the install message signature from the service.
     *
     * @param message signature base to sign
     * @return base64 encoded signature
     * @throws ApproovException if signing fails
     */
    protected String getInstallMessageSignature(String message) throws ApproovException {
        return ApproovService.getInstallMessageSignature(message);
    }

    /**
     * Retrieves the account message signature from the service.
     *
     * @param message signature base to sign
     * @return base64 encoded signature
     * @throws ApproovException if signing fails
     */
    protected String getAccountMessageSignature(String message) throws ApproovException {
        return ApproovService.getAccountMessageSignature(message);
    }

    /**
     * Decodes a base64 value to bytes.
     *
     * @param base64 base64 encoded data
     * @return decoded bytes
     */
    protected byte[] decodeBase64(String base64) {
        return Base64.decode(base64, Base64.NO_WRAP);
    }

    private static void removeHeaderIgnoreCase(Map<String, String> headers, String name) {
        List<String> matchingKeys = new ArrayList<>();
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                matchingKeys.add(key);
            }
        }
        for (String key : matchingKeys) {
            headers.remove(key);
        }
    }

    private static void removeSignatureHeaders(Map<String, String> headers) {
        removeHeaderIgnoreCase(headers, "Signature");
        removeHeaderIgnoreCase(headers, "Signature-Input");
        removeHeaderIgnoreCase(headers, "Signature-Base-Digest");
    }

    /**
     * Converts an ASN.1 DER encoded ECDSA P-256 signature, as the SDK returns the install message signature,
     * to the raw 64 byte r||s form that ecdsa-p256-sha256 requires. Only the canonical DER encoding of the
     * result is accepted, since the Tink conversion does not check that r and s fit in 32 bytes.
     *
     * @param der is the DER encoded signature
     * @return the raw r||s signature
     * @throws IllegalArgumentException if der is not a canonical DER ES256 signature
     */
    static byte[] es256DerToRaw(byte[] der) {
        byte[] raw;
        byte[] canonical;
        try {
            raw = EllipticCurves.ecdsaDer2Ieee(der, 64);
            canonical = EllipticCurves.ecdsaIeee2Der(raw);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException("Not an ASN.1 DER ES256 signature: " + e, e);
        }
        if (!Arrays.equals(canonical, der))
            throw new IllegalArgumentException("Not an ASN.1 DER ES256 signature: integer exceeds 32 bytes");
        return raw;
    }

    /**
     * Adds message signing headers to requests that already received an Approov token. The processed headers
     * hook of the mutator whose decisions the signer makes is called first, so that the signature covers any
     * change it makes.
     * <p>
     * Message signing is fail-open. If a signature cannot be produced, for either install (ES256) or account
     * (HS256) signing, because it is unavailable or empty or an ASN.1/base64 decode fails, it is left out
     * and the request is signed with the other one, or sent unsigned if neither can be produced. The only
     * fail-closed cases are an unsupported signing algorithm and a body digest configured as required that
     * cannot be generated; both raise an {@code ApproovException}. The backend remains the enforcement point
     * for message signatures.
     */
    @Override
    public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
            ApproovRequestMutations changes) throws ApproovException {
        // the decisions make their changes before signing, and an exception they throw is theirs rather than a
        // signing decision
        Map<String, String> processed = decisions().handleRequestProcessedHeaders(request, headers, changes);
        if (processed == null)
            return null;
        try {
            return sign(request, processed, changes);
        } catch (ApproovException e) {
            // the signing decisions keep their own type rather than being reported as a failing mutator hook
            throw ApproovService.standardDecision(e);
        }
    }

    private Map<String, String> sign(Request<?> request, Map<String, String> headers,
            ApproovRequestMutations changes) throws ApproovException {
        if (changes == null || changes.getTokenHeaderKey() == null) {
            return headers;
        }

        VolleyComponentProvider provider;
        try {
            provider = new VolleyComponentProvider(request, headers);
        } catch (RuntimeException e) {
            // Fail-open: a request whose parts cannot be read is sent unsigned
            ApproovLog.e(TAG, "Message signing: failed to read the request, proceeding unsigned: " + e);
            Map<String, String> unsigned = new LinkedHashMap<>(headers);
            removeSignatureHeaders(unsigned);
            return unsigned;
        }
        Map<String, String> originalHeaders = new LinkedHashMap<>(provider.getHeaders());
        boolean hadContentDigest = provider.hasField("Content-Digest");

        // Message signing is fail-open. Only two conditions fail closed and abort the request: (1) a body
        // digest configured as required that cannot be generated, and (2) an unsupported signing algorithm.
        // Building the signature parameters only aborts the request for the first, while any other failure
        // (including from a custom factory or subclass) leaves the request unsigned, as the backend is the
        // enforcement point.
        SignatureParameters params;
        try {
            params = buildSignatureParameters(provider, changes);
        } catch (RequiredBodyDigestException e) {
            throw new ApproovException(e.getMessage(), e);
        } catch (RuntimeException e) {
            ApproovLog.e(TAG, "Message signing: failed to build signature parameters, proceeding unsigned: " + e);
            removeSignatureHeaders(originalHeaders);
            return originalHeaders;
        }
        if (params == null) {
            removeSignatureHeaders(originalHeaders);
            return originalHeaders;
        }

        // Everything below is fail-open: any failure to obtain, decode, or serialize a signature leaves that
        // signature out. The single exception is an unsupported algorithm, which is thrown as
        // ApproovException (checked, so it is NOT caught by the fail-open RuntimeException handler and
        // propagates to abort the request).
        try {
            // determine the algorithms to sign with, which is a single algorithm if the factory sets one
            // explicitly on the parameters, or otherwise the algorithms configured on the factory (by default
            // the install signature only)
            List<String> algs;
            if (params.getAlg() != null) {
                algs = Collections.singletonList(params.getAlg());
            } else {
                SignatureParametersFactory factory = factoryFor(provider);
                try {
                    // a factory with no algorithm enabled throws IllegalStateException here
                    algs = (factory != null) ? factory.getAlgs() : Collections.singletonList(ALG_ES256);
                } catch (RuntimeException e) {
                    ApproovLog.e(TAG, "Message signing: no usable algorithm, proceeding unsigned: " + e);
                    removeSignatureHeaders(originalHeaders);
                    return originalHeaders;
                }
                if (algs == null || algs.isEmpty()) {
                    ApproovLog.e(TAG, "Message signing: no usable algorithm, proceeding unsigned: empty algorithm list");
                    removeSignatureHeaders(originalHeaders);
                    return originalHeaders;
                }
            }
            for (String alg : algs) {
                // an unsupported algorithm is a configuration error and fails closed
                if (!ALG_ES256.equals(alg) && !ALG_HS256.equals(alg))
                    throw new ApproovException("Message signing: unsupported algorithm identifier: " + alg);
            }

            // generate a signature per algorithm over the same covered components, each with its own signature
            // base since the base includes the algorithm
            Map<String, ListElement<?>> signatures = new LinkedHashMap<>();
            Map<String, ListElement<?>> signatureInputs = new LinkedHashMap<>();
            Map<String, String> messages = new LinkedHashMap<>();
            // the reason each signature that could not be produced is missing, by signature identifier
            Map<String, String> missing = new LinkedHashMap<>();
            for (String alg : algs) {
                SignatureParameters algParams = new SignatureParameters(params).setAlg(alg);
                // WARNING never log the message as it contains an Approov token which provides access to
                // your API
                String message = new SignatureBaseBuilder(algParams, provider).createSignatureBase();
                String sigId = ALG_ES256.equals(alg) ? SIG_ID_INSTALL : SIG_ID_ACCOUNT;
                byte[] signature = ALG_ES256.equals(alg) ? installSignature(message, missing)
                        : accountSignature(message, missing);
                if (signature == null) {
                    // this signature could not be produced so we proceed with any other
                    continue;
                }
                signatures.put(sigId, ByteSequenceItem.valueOf(signature));
                signatureInputs.put(sigId, algParams.toComponentValue());
                messages.put(sigId, message);
            }
            if (signatures.isEmpty()) {
                StringBuilder line = new StringBuilder("Message signing: no signature produced, proceeding unsigned");
                for (Map.Entry<String, String> entry : missing.entrySet())
                    line.append(": ").append(entry.getKey()).append(" signature ").append(entry.getValue());
                if (unsignedLogged.compareAndSet(false, true))
                    ApproovLog.e(TAG, line.toString());
                else
                    ApproovLog.d(TAG, line.toString());
                removeSignatureHeaders(originalHeaders);
                return originalHeaders;
            }
            for (Map.Entry<String, String> entry : missing.entrySet()) {
                String line = "Message signing: " + entry.getKey() + " signature " + entry.getValue()
                        + ", signed without it";
                AtomicBoolean logged = SIG_ID_INSTALL.equals(entry.getKey()) ? installMissingLogged : accountMissingLogged;
                if (logged.compareAndSet(false, true))
                    ApproovLog.w(TAG, line);
                else
                    ApproovLog.d(TAG, line);
            }

            // each signature is a Byte Sequence member of the same Signature and Signature-Input dictionaries,
            // serialized as colon delimited base64 (for example install=:<base64>:)
            String sigHeader = Dictionary.valueOf(signatures).serialize();
            String sigInputHeader = Dictionary.valueOf(signatureInputs).serialize();

            Map<String, String> signedHeaders = new LinkedHashMap<>(provider.getHeaders());
            removeHeaderIgnoreCase(signedHeaders, "Signature");
            removeHeaderIgnoreCase(signedHeaders, "Signature-Input");
            removeHeaderIgnoreCase(signedHeaders, "Signature-Base-Digest");
            signedHeaders.put("Signature", sigHeader);
            signedHeaders.put("Signature-Input", sigInputHeader);

            List<String> addedHeaderKeys = new ArrayList<>();
            if (!hadContentDigest && provider.hasField("Content-Digest")) {
                addedHeaderKeys.add("Content-Digest");
            }
            addedHeaderKeys.add("Signature");
            addedHeaderKeys.add("Signature-Input");

            if (params.isDebugMode()) {
                try {
                    MessageDigest digestBuilder = MessageDigest.getInstance("SHA-256");
                    Map<String, ListElement<?>> digests = new LinkedHashMap<>();
                    for (Map.Entry<String, String> entry : messages.entrySet()) {
                        digestBuilder.reset();
                        byte[] digest = digestBuilder.digest(entry.getValue().getBytes(StandardCharsets.UTF_8));
                        digests.put(entry.getKey(), ByteSequenceItem.valueOf(digest));
                    }
                    signedHeaders.put("Signature-Base-Digest", Dictionary.valueOf(digests).serialize());
                    addedHeaderKeys.add("Signature-Base-Digest");
                } catch (NoSuchAlgorithmException e) {
                    ApproovLog.d(TAG, "Message signing: digest algorithm unavailable, no debug entry: " + e);
                }
            }

            changes.setAddedHeaderKeys(addedHeaderKeys);
            return signedHeaders;
        } catch (RuntimeException e) {
            // Fail-open: any other signing failure (signature-base component missing, URL that cannot be
            // read, serialization, etc.) is logged and the request proceeds unsigned. ApproovException is
            // checked and is NOT caught here, so the unsupported-algorithm fail-closed path propagates.
            ApproovLog.e(TAG, "Message signing failed - proceeding unsigned: " + e, e);
            removeSignatureHeaders(originalHeaders);
            return originalHeaders;
        }
    }

    /**
     * Produces the install message signature over the given message as the raw 64 byte r||s value that
     * ecdsa-p256-sha256 requires.
     *
     * @param message the signature base
     * @param missing receives the reason if the signature is not available
     * @return the signature bytes, or null if not available
     */
    private byte[] installSignature(String message, Map<String, String> missing) {
        String base64;
        try {
            base64 = getInstallMessageSignature(message);
        } catch (ApproovException e) {
            missing.put(SIG_ID_INSTALL, "unavailable: " + e);
            return null;
        }
        if (base64 == null || base64.isEmpty()) {
            missing.put(SIG_ID_INSTALL, "unavailable");
            return null;
        }
        byte[] signature;
        try {
            signature = decodeBase64(base64);
        } catch (RuntimeException e) {
            missing.put(SIG_ID_INSTALL, "not base64: " + e);
            return null;
        }
        // decode the signature from ASN.1 DER format
        try {
            return es256DerToRaw(signature);
        } catch (RuntimeException e) {
            missing.put(SIG_ID_INSTALL, "not ASN.1 DER ES256: " + e);
            return null;
        }
    }

    /**
     * Produces the account message signature over the given message, which may not be available as the
     * account key is only delivered on a successful attestation.
     *
     * @param message the signature base
     * @param missing receives the reason if the signature is not available
     * @return the signature bytes, or null if not available
     */
    private byte[] accountSignature(String message, Map<String, String> missing) {
        String base64;
        try {
            base64 = getAccountMessageSignature(message);
        } catch (ApproovException e) {
            missing.put(SIG_ID_ACCOUNT, "unavailable: " + e);
            return null;
        }
        if (base64 == null || base64.isEmpty()) {
            missing.put(SIG_ID_ACCOUNT, "unavailable");
            return null;
        }
        try {
            return decodeBase64(base64);
        } catch (RuntimeException e) {
            missing.put(SIG_ID_ACCOUNT, "not base64: " + e);
            return null;
        }
    }

    /**
     * Generates a default SignatureParametersFactory with predefined settings.
     *
     * @return a new SignatureParametersFactory
     */
    public static SignatureParametersFactory generateDefaultSignatureParametersFactory() {
        return generateDefaultSignatureParametersFactory(null);
    }

    /**
     * Generates a default SignatureParametersFactory with optional base parameters.
     *
     * @param baseParametersOverride the base parameters to override, or null to use defaults
     * @return a new SignatureParametersFactory
     */
    public static SignatureParametersFactory generateDefaultSignatureParametersFactory(
            SignatureParameters baseParametersOverride) {
        long defaultExpiresLifetime = 15;
        SignatureParameters baseParameters;
        if (baseParametersOverride != null) {
            baseParameters = baseParametersOverride;
        } else {
            baseParameters = new SignatureParameters()
                    .addComponentIdentifier(ComponentProvider.DC_METHOD)
                    .addComponentIdentifier(ComponentProvider.DC_TARGET_URI);
        }
        return new SignatureParametersFactory()
                .setBaseParameters(baseParameters)
                .setUseInstallMessageSigning()
                .setAddCreated(true)
                .setExpiresLifetime(defaultExpiresLifetime)
                .setAddApproovTokenHeader(true)
                .setAddApproovTraceIDHeader(true)
                .addOptionalHeaders("Authorization", "Content-Length", "Content-Type")
                .setBodyDigestConfig(DIGEST_SHA256, false);
    }

    /**
     * Factory for generating request-specific signature parameters.
     */
    public static class SignatureParametersFactory {
        protected SignatureParameters baseParameters = new SignatureParameters();
        protected String bodyDigestAlgorithm;
        protected boolean bodyDigestRequired;
        // true to produce the install message signature (ECDSA P-256 with the per installation key)
        protected boolean useInstallMessageSigning = true;
        // true to produce the account message signature (HMAC-SHA256 with the account key), so that by
        // default a bare factory produces the install signature only
        protected boolean useAccountMessageSigning;
        protected boolean addCreated;
        protected long expiresLifetime;
        protected boolean addApproovTokenHeader;
        protected boolean addApproovTraceIDHeader;
        protected List<String> optionalHeaders = new ArrayList<>();

        /**
         * Sets the base parameters copied for each message signature.
         *
         * @param baseParameters the base parameters to set
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setBaseParameters(SignatureParameters baseParameters) {
            this.baseParameters = baseParameters;
            return this;
        }

        /**
         * Configures body digest settings.
         *
         * @param bodyDigestAlgorithm the digest algorithm to use, or null to disable
         * @param required whether a digest is required
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setBodyDigestConfig(String bodyDigestAlgorithm, boolean required) {
            if (bodyDigestAlgorithm == null) {
                required = false;
            } else if (!DIGEST_SHA256.equals(bodyDigestAlgorithm) && !DIGEST_SHA512.equals(bodyDigestAlgorithm)) {
                throw new IllegalArgumentException("Unsupported body digest algorithm: " + bodyDigestAlgorithm);
            }
            this.bodyDigestAlgorithm = bodyDigestAlgorithm;
            this.bodyDigestRequired = required;
            return this;
        }

        /**
         * Sets the factory to produce only the install message signature. This is the default of a newly
         * constructed factory and of generateDefaultSignatureParametersFactory().
         *
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setUseInstallMessageSigning() {
            this.useInstallMessageSigning = true;
            this.useAccountMessageSigning = false;
            return this;
        }

        /**
         * Sets the factory to produce only the account message signature.
         *
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setUseAccountMessageSigning() {
            this.useInstallMessageSigning = false;
            this.useAccountMessageSigning = true;
            return this;
        }

        /**
         * Sets the factory to produce both the install and the account message signatures, as the members
         * "install" and "account" of the same Signature and Signature-Input headers over the same covered
         * components.
         *
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setUseInstallAndAccountMessageSigning() {
            this.useInstallMessageSigning = true;
            this.useAccountMessageSigning = true;
            return this;
        }

        /**
         * Gets the signature algorithms configured on this factory, in the order the signatures are emitted.
         *
         * @return the algorithm identifiers
         * @throws IllegalStateException if neither signature is enabled
         */
        public List<String> getAlgs() {
            List<String> algs = new ArrayList<>(2);
            if (useInstallMessageSigning)
                algs.add(ALG_ES256);
            if (useAccountMessageSigning)
                algs.add(ALG_HS256);
            if (algs.isEmpty())
                throw new IllegalStateException("No message signing algorithm is enabled");
            return algs;
        }

        /**
         * Sets whether the created field should be added.
         *
         * @param addCreated whether to add the created field
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setAddCreated(boolean addCreated) {
            this.addCreated = addCreated;
            return this;
        }

        /**
         * Sets the expires lifetime in seconds.
         *
         * @param expiresLifetime expiration lifetime in seconds
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setExpiresLifetime(long expiresLifetime) {
            this.expiresLifetime = expiresLifetime;
            return this;
        }

        /**
         * Sets whether the Approov token header should be signed.
         *
         * @param addApproovTokenHeader whether the token header should be included
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setAddApproovTokenHeader(boolean addApproovTokenHeader) {
            this.addApproovTokenHeader = addApproovTokenHeader;
            return this;
        }

        /**
         * Sets whether the Approov TraceID header should be signed when present.
         *
         * @param addApproovTraceIDHeader whether the trace ID header should be included
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setAddApproovTraceIDHeader(boolean addApproovTraceIDHeader) {
            this.addApproovTraceIDHeader = addApproovTraceIDHeader;
            return this;
        }

        /**
         * Adds optional headers to include when present.
         *
         * @param headers headers to add
         * @return the current instance for chaining
         */
        public SignatureParametersFactory addOptionalHeaders(String... headers) {
            if (this.optionalHeaders == null) {
                this.optionalHeaders = new ArrayList<>(Arrays.asList(headers));
            } else {
                this.optionalHeaders.addAll(Arrays.asList(headers));
            }
            return this;
        }

        protected boolean generateBodyDigest(VolleyComponentProvider provider, SignatureParameters requestParameters) {
            byte[] body = provider.getRequestBody();
            if (body == null || body.length == 0) {
                return false;
            }

            String digestAlgorithmName;
            switch (bodyDigestAlgorithm) {
                case DIGEST_SHA256:
                    digestAlgorithmName = "SHA-256";
                    break;
                case DIGEST_SHA512:
                    digestAlgorithmName = "SHA-512";
                    break;
                default:
                    return false;
            }

            byte[] digest;
            try {
                MessageDigest digestBuilder = MessageDigest.getInstance(digestAlgorithmName);
                digestBuilder.reset();
                digest = digestBuilder.digest(body);
            } catch (NoSuchAlgorithmException e) {
                return false;
            }

            String digestHeader = Dictionary.valueOf(Collections.singletonMap(
                    bodyDigestAlgorithm, ByteSequenceItem.valueOf(digest))).serialize();
            provider.setHeader("Content-Digest", digestHeader);
            requestParameters.addComponentIdentifier("Content-Digest");
            return true;
        }

        /**
         * Builds the signature parameters for a request.
         *
         * @param provider the component provider for the request
         * @param changes the mutations applied to the request by Approov
         * @return the signature parameters
         * @throws RequiredBodyDigestException if a body digest configured as required cannot be generated
         */
        protected SignatureParameters buildSignatureParameters(VolleyComponentProvider provider,
                ApproovRequestMutations changes) {
            // the algorithm is left unset so that one signature per configured algorithm is produced over
            // these same parameters, while a subclass may set an explicit algorithm for a single signature
            SignatureParameters requestParameters = new SignatureParameters(baseParameters);
            if (addCreated || expiresLifetime > 0) {
                long currentTime = ApproovService.signatureTimeMillis() / 1000;
                if (addCreated) {
                    requestParameters.setCreated(currentTime);
                }
                if (expiresLifetime > 0) {
                    requestParameters.setExpires(currentTime + expiresLifetime);
                }
            }
            if (addApproovTokenHeader && changes.getTokenHeaderKey() != null) {
                requestParameters.addComponentIdentifier(changes.getTokenHeaderKey());
            }
            if (addApproovTraceIDHeader && changes.getTraceIDHeaderKey() != null) {
                requestParameters.addComponentIdentifier(changes.getTraceIDHeaderKey());
            }
            if (optionalHeaders != null) {
                for (String headerName : optionalHeaders) {
                    if (provider.hasField(headerName)) {
                        requestParameters.addComponentIdentifier(headerName);
                    }
                }
            }
            if (bodyDigestAlgorithm != null) {
                if (!generateBodyDigest(provider, requestParameters) && bodyDigestRequired) {
                    throw new RequiredBodyDigestException("Message signing: required body digest not generated");
                }
            }
            return requestParameters;
        }
    }

    // RequiredBodyDigestException is thrown if a body digest configured as required cannot be generated, which
    // aborts the request: the request fails with an ApproovException that has it as its cause
    public static class RequiredBodyDigestException extends IllegalStateException {
        /**
         * Constructs an exception due to a required body digest that cannot be generated.
         *
         * @param message is the basic information about the exception cause
         */
        public RequiredBodyDigestException(String message) {
            super(message);
        }
    }

    /**
     * ComponentProvider implementation for Volley requests, deriving every component from the request URL
     * string exactly as the stack sends it, and never parsing it with java.net.URI, which encodes some
     * characters differently and rejects some URLs the stack sends. The URL is read with java.net.URL, as
     * the stack does.
     * <p>
     * Some derived components deliberately deviate from a strict reading of RFC 9421 so that all Approov
     * service layers produce identical signature bases for the Approov verifier:
     * <ul>
     * <li>{@code @authority} is the lowercase host and a non-default port; a default port is left out
     * (RFC 9421 section 2.2.3);</li>
     * <li>{@code @target-uri} is the request URL as provided to Volley without any fragment, which is never
     * sent, and without an explicit default port (RFC 9421 section 2.2.2);</li>
     * <li>{@code @query} is the query as sent with its leading {@code ?}, or {@code ?} alone when the URL has
     * no query (RFC 9421 section 2.2.7), as the OkHttp layer builds it.</li>
     * </ul>
     * Any change here must be coordinated with the other service layers and the
     * verifier, otherwise signatures stop validating.
     */
    protected static final class VolleyComponentProvider implements ComponentProvider {
        private final Request<?> request;
        private final String urlString;
        private final Map<String, String> headers;
        // the parsed URL, read when a component needs it so that a URL that cannot be parsed only fails
        // the components that use it
        private URL parsedUrl;

        VolleyComponentProvider(Request<?> request, Map<String, String> headers) {
            this.request = request;
            this.urlString = request.getUrl();
            this.headers = new LinkedHashMap<>();
            try {
                Map<String, String> requestHeaders = request.getHeaders();
                if (requestHeaders != null) {
                    this.headers.putAll(requestHeaders);
                }
            } catch (AuthFailureError e) {
                ApproovLog.d(TAG, "Unable to fetch request headers for message signing " + e);
            }
            if (headers != null) {
                this.headers.putAll(headers);
            }
        }

        // gets the request URL as the stack reads it
        private URL url() {
            if (parsedUrl == null) {
                try {
                    parsedUrl = new URL(urlString);
                } catch (MalformedURLException e) {
                    throw new IllegalArgumentException("Request URL cannot be read: " + e.getMessage(), e);
                }
            }
            return parsedUrl;
        }

        /**
         * Gets the host of the request without any port, in lowercase, which is used to select a host
         * factory. An IPv6 address keeps its brackets.
         *
         * @return the host of the request
         */
        String getHost() {
            return url().getHost().toLowerCase(Locale.ROOT);
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public void setHeader(String name, String value) {
            List<String> matchingKeys = new ArrayList<>();
            for (String key : headers.keySet()) {
                if (key.equalsIgnoreCase(name)) {
                    matchingKeys.add(key);
                }
            }
            for (String key : matchingKeys) {
                headers.remove(key);
            }
            headers.put(name, value);
        }

        private String findHeaderValue(String name) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(name)) {
                    return entry.getValue();
                }
            }
            return null;
        }

        public byte[] getRequestBody() {
            try {
                return request.getBody();
            } catch (AuthFailureError e) {
                ApproovLog.d(TAG, "Unable to fetch request body for message signing " + e);
                return null;
            }
        }

        @Override
        public String getMethod() {
            switch (request.getMethod()) {
                case Request.Method.DEPRECATED_GET_OR_POST:
                    return "GET";
                case Request.Method.GET:
                    return "GET";
                case Request.Method.POST:
                    return "POST";
                case Request.Method.PUT:
                    return "PUT";
                case Request.Method.DELETE:
                    return "DELETE";
                case Request.Method.HEAD:
                    return "HEAD";
                case Request.Method.OPTIONS:
                    return "OPTIONS";
                case Request.Method.TRACE:
                    return "TRACE";
                case Request.Method.PATCH:
                    return "PATCH";
                default:
                    throw new IllegalStateException("Unsupported request method: " + request.getMethod());
            }
        }

        /**
         * Gets the @authority derived component, which is the lowercase host, in brackets for an IPv6
         * address, followed by the port only if it is not the default port of the scheme.
         *
         * @return the authority of the request
         */
        @Override
        public String getAuthority() {
            URL url = url();
            String authority = getHost();
            if (url.getPort() != -1 && url.getPort() != url.getDefaultPort())
                authority += ":" + url.getPort();
            return authority;
        }

        @Override
        public String getScheme() {
            return url().getProtocol();
        }

        /**
         * Gets the @target-uri derived component, which is the request URL as the stack sends it, leaving
         * out any fragment as that is never sent, and any explicit default port (":443" for https and ":80"
         * for http, the scheme being compared without regard to case). Nothing else changes, so the path,
         * the query and their percent-encoding are as the app wrote them. An absent path is the root path,
         * as the stack sends it.
         *
         * @return the target URI of the request
         */
        @Override
        public String getTargetUri() {
            URL url = url();
            String text = urlString;
            int fragment = text.indexOf('#');
            if (fragment >= 0)
                text = text.substring(0, fragment);

            // the authority runs from after "://" to the first of "/", "?" or the end of the text
            int authorityStart = text.indexOf("://") + 3;
            int authorityEnd = text.length();
            for (int i = authorityStart; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c == '/' || c == '?') {
                    authorityEnd = i;
                    break;
                }
            }
            String authority = text.substring(authorityStart, authorityEnd);
            // an explicit port follows the last colon after any user info and any IPv6 address in brackets
            int portColon = authority.lastIndexOf(':');
            if (portColon > authority.lastIndexOf(']') && portColon > authority.lastIndexOf('@')
                    && url.getPort() == url.getDefaultPort() && url.getPort() != -1)
                authority = authority.substring(0, portColon);
            String rest = text.substring(authorityEnd);
            if (rest.isEmpty() || rest.charAt(0) == '?')
                rest = "/" + rest;
            return text.substring(0, authorityStart) + authority + rest;
        }

        @Override
        public String getRequestTarget() {
            String requestTarget = getPath();
            String query = url().getQuery();
            if (query != null) {
                requestTarget += "?" + query;
            }
            return requestTarget;
        }

        @Override
        public String getPath() {
            String path = url().getPath();
            return (path == null || path.isEmpty()) ? "/" : path;
        }

        /**
         * Gets the @query derived component, which is the query as sent with its leading "?", or "?" alone if
         * there is none.
         *
         * @return the query of the request
         */
        @Override
        public String getQuery() {
            String query = url().getQuery();
            return (query == null) ? "?" : "?" + query;
        }

        @Override
        public String getQueryParam(String name) {
            List<String> values = Uri.parse(urlString).getQueryParameters(name);
            if (values.isEmpty()) {
                throw new IllegalArgumentException("Could not find query parameter named " + name);
            } else if (values.size() > 1) {
                return null;
            }
            return values.get(0);
        }

        @Override
        public String getStatus() {
            throw new IllegalStateException("Only requests are supported");
        }

        @Override
        public boolean hasField(String name) {
            return findHeaderValue(name) != null;
        }

        @Override
        public String getField(String name) {
            return findHeaderValue(name);
        }

        @Override
        public boolean hasBody() {
            byte[] body = getRequestBody();
            return body != null && body.length > 0;
        }
    }
}
