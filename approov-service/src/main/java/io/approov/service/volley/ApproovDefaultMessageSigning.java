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
import android.util.Log;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;

import io.approov.internal.volley.bouncycastle.asn1.ASN1InputStream;
import io.approov.internal.volley.bouncycastle.asn1.ASN1Integer;
import io.approov.internal.volley.bouncycastle.asn1.ASN1Sequence;

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.approov.util.http.sfv.ByteSequenceItem;
import io.approov.util.http.sfv.Dictionary;
import io.approov.util.sig.ComponentProvider;
import io.approov.util.sig.SignatureBaseBuilder;
import io.approov.util.sig.SignatureParameters;

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

    protected SignatureParametersFactory defaultFactory;
    protected final Map<String, SignatureParametersFactory> hostFactories;

    /**
     * Constructs a new message signing mutator.
     */
    public ApproovDefaultMessageSigning() {
        hostFactories = new HashMap<>();
    }

    @Override
    public String toString() {
        return "ApproovDefaultMessageSigning";
    }

    /**
     * Sets the default factory for generating signature parameters.
     *
     * @param factory the factory to set as the default
     * @return the current instance for chaining
     */
    public ApproovDefaultMessageSigning setDefaultFactory(SignatureParametersFactory factory) {
        this.defaultFactory = factory;
        return this;
    }

    /**
     * Associates a specific host with a signature parameters factory.
     *
     * @param hostName the host name
     * @param factory the factory to associate with the host
     * @return the current instance for chaining
     */
    public ApproovDefaultMessageSigning putHostFactory(String hostName, SignatureParametersFactory factory) {
        this.hostFactories.put(hostName, factory);
        return this;
    }

    protected SignatureParameters buildSignatureParameters(VolleyComponentProvider provider,
            ApproovRequestMutations changes) {
        SignatureParametersFactory factory = hostFactories.get(provider.getAuthority());
        if (factory == null) {
            factory = defaultFactory;
            if (factory == null) {
                return null;
            }
        }
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

    private static byte[] to32ByteArray(ASN1Integer bytesAsASN1Integer) {
        BigInteger bytesAsBigInteger = bytesAsASN1Integer.getValue();
        byte[] bytes = bytesAsBigInteger.toByteArray();
        byte[] bytes32;
        if (bytes.length < 32) {
            bytes32 = new byte[32];
            System.arraycopy(bytes, 0, bytes32, 32 - bytes.length, bytes.length);
        } else if (bytes.length == 32) {
            bytes32 = bytes;
        } else if (bytes.length == 33 && bytes[0] == 0) {
            bytes32 = new byte[32];
            System.arraycopy(bytes, 1, bytes32, 0, 32);
        } else {
            throw new IllegalArgumentException("Not an ASN.1 DER ES256 signature part");
        }
        return bytes32;
    }

    /**
     * Adds message signing headers to requests that already received an Approov token.
     * <p>
     * Failure handling is intentionally asymmetric between the two algorithms: an install
     * (ES256) signature failure is logged and the request proceeds unsigned, because the
     * install keypair may legitimately be unavailable on a device; an account (HS256)
     * signature failure propagates and fails the request, because the account secret is
     * expected to always be available once configured.
     */
    @Override
    public Map<String, String> handleRequestProcessedHeaders(Request<?> request, Map<String, String> headers,
            ApproovRequestMutations changes) throws ApproovException {
        if (changes == null || changes.getTokenHeaderKey() == null) {
            return headers;
        }

        VolleyComponentProvider provider = new VolleyComponentProvider(request, headers);
        Map<String, String> originalHeaders = new LinkedHashMap<>(provider.getHeaders());
        boolean hadContentDigest = provider.hasField("Content-Digest");

        // Message signing is fail-open (TESTING_REQUIREMENTS §5). Only two conditions fail closed and
        // abort the request: (1) a REQUIRED body digest that cannot be generated, and (2) an
        // unsupported signing algorithm. buildSignatureParameters is where a required digest is
        // enforced, so it runs first and its failure is surfaced as ApproovException (fail closed).
        SignatureParameters params;
        try {
            params = buildSignatureParameters(provider, changes);
        } catch (RuntimeException e) {
            throw new ApproovException("Required body digest could not be generated: " + e.getMessage(), e);
        }
        if (params == null) {
            removeSignatureHeaders(originalHeaders);
            return originalHeaders;
        }

        // Everything below is fail-open: any failure to obtain, decode, or serialize a signature logs
        // at error level and proceeds unsigned. The single exception is an unsupported algorithm, which
        // is thrown as ApproovException (checked, so it is NOT caught by the fail-open RuntimeException
        // handler and propagates to abort the request).
        try {
            String message = new SignatureBaseBuilder(params, provider).createSignatureBase();

            String sigId;
            byte[] signature;
            switch (params.getAlg()) {
                case ALG_ES256: {
                    sigId = "install";
                    String base64;
                    try {
                        base64 = getInstallMessageSignature(message);
                    } catch (ApproovException e) {
                        Log.e(TAG, "Install message signature unavailable - proceeding unsigned: " + e);
                        removeSignatureHeaders(originalHeaders);
                        return originalHeaders;
                    }
                    if (base64.isEmpty()) {
                        Log.e(TAG, "Install message signature empty - proceeding unsigned");
                        removeSignatureHeaders(originalHeaders);
                        return originalHeaders;
                    }
                    signature = decodeBase64(base64);
                    try (ASN1InputStream asn1InputStream = new ASN1InputStream(signature)) {
                        Object obj = asn1InputStream.readObject();
                        if (obj instanceof ASN1Sequence) {
                            ASN1Sequence sequence = (ASN1Sequence) obj;
                            byte[] rBytes = to32ByteArray((ASN1Integer) sequence.getObjectAt(0));
                            byte[] sBytes = to32ByteArray((ASN1Integer) sequence.getObjectAt(1));
                            signature = new byte[rBytes.length + sBytes.length];
                            System.arraycopy(rBytes, 0, signature, 0, rBytes.length);
                            System.arraycopy(sBytes, 0, signature, rBytes.length, sBytes.length);
                        } else {
                            throw new IllegalStateException("Not an ASN1Sequence");
                        }
                    } catch (Exception e) {
                        // Fail-open: a malformed install signature is logged and the request proceeds unsigned.
                        Log.e(TAG, "Failed to decode ASN.1 DER ES256 signature - proceeding unsigned: " + e, e);
                        removeSignatureHeaders(originalHeaders);
                        return originalHeaders;
                    }
                    break;
                }
                case ALG_HS256: {
                    sigId = "account";
                    String base64;
                    try {
                        base64 = getAccountMessageSignature(message);
                    } catch (ApproovException e) {
                        Log.e(TAG, "Account message signature unavailable - proceeding unsigned: " + e);
                        removeSignatureHeaders(originalHeaders);
                        return originalHeaders;
                    }
                    if (base64.isEmpty()) {
                        Log.e(TAG, "Account message signature empty - proceeding unsigned");
                        removeSignatureHeaders(originalHeaders);
                        return originalHeaders;
                    }
                    signature = decodeBase64(base64);
                    break;
                }
                default:
                    // Unsupported algorithm fails closed.
                    throw new ApproovException("Unsupported algorithm identifier: " + params.getAlg());
            }

            String sigHeader = Dictionary.valueOf(Collections.singletonMap(
                    sigId, ByteSequenceItem.valueOf(signature))).serialize();
            String sigInputHeader = Dictionary.valueOf(Collections.singletonMap(
                    sigId, params.toComponentValue())).serialize();

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
                    digestBuilder.reset();
                    byte[] digest = digestBuilder.digest(message.getBytes(StandardCharsets.UTF_8));
                    String digestHeader = Dictionary.valueOf(Collections.singletonMap(
                            DIGEST_SHA256, ByteSequenceItem.valueOf(digest))).serialize();
                    signedHeaders.put("Signature-Base-Digest", digestHeader);
                    addedHeaderKeys.add("Signature-Base-Digest");
                } catch (NoSuchAlgorithmException e) {
                    Log.d(TAG, "Failed to get digest algorithm - no debug entry " + e);
                }
            }

            changes.setAddedHeaderKeys(addedHeaderKeys);
            return signedHeaders;
        } catch (RuntimeException e) {
            // Fail-open: any other signing failure (signature-base component missing, base64 decode,
            // serialization, etc.) is logged and the request proceeds unsigned. ApproovException is
            // checked and is NOT caught here, so the unsupported-algorithm fail-closed path propagates.
            Log.e(TAG, "Message signing failed - proceeding unsigned: " + e, e);
            removeSignatureHeaders(originalHeaders);
            return originalHeaders;
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
         * Uses install message signing.
         *
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setUseInstallMessageSigning() {
            this.useAccountMessageSigning = false;
            return this;
        }

        /**
         * Uses account message signing.
         *
         * @return the current instance for chaining
         */
        public SignatureParametersFactory setUseAccountMessageSigning() {
            this.useAccountMessageSigning = true;
            return this;
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

        protected SignatureParameters buildSignatureParameters(VolleyComponentProvider provider,
                ApproovRequestMutations changes) {
            SignatureParameters requestParameters = new SignatureParameters(baseParameters);
            if (useAccountMessageSigning) {
                requestParameters.setAlg(ALG_HS256);
            } else {
                requestParameters.setAlg(ALG_ES256);
            }
            if (addCreated || expiresLifetime > 0) {
                long currentTime = System.currentTimeMillis() / 1000;
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
                    throw new IllegalStateException("Failed to create required body digest");
                }
            }
            return requestParameters;
        }
    }

    /**
     * ComponentProvider implementation for Volley requests.
     * <p>
     * Note that some derived components deliberately deviate from a strict reading of
     * RFC 9421 so that all Approov service layers produce identical signature bases for
     * the Approov verifier:
     * <ul>
     * <li>{@code @authority} is the host only and never includes a port (RFC 9421
     * section 2.2.3 includes non-default ports);</li>
     * <li>{@code @target-uri} is the full request URL as provided to Volley, including
     * any fragment (RFC 9421 section 2.2.2 excludes fragments);</li>
     * <li>{@code @query} has no leading {@code ?} and is unavailable when the URL has
     * no query (RFC 9421 section 2.2.7 includes the {@code ?} and uses {@code ?} alone
     * for an absent query).</li>
     * </ul>
     * Any change here must be coordinated with the other service layers and the
     * verifier, otherwise signatures stop validating.
     */
    protected static final class VolleyComponentProvider implements ComponentProvider {
        private final Request<?> request;
        private final Uri androidUri;
        private final URI javaUri;
        private final Map<String, String> headers;

        VolleyComponentProvider(Request<?> request, Map<String, String> headers) {
            this.request = request;
            this.androidUri = Uri.parse(request.getUrl());
            this.javaUri = URI.create(request.getUrl());
            this.headers = new LinkedHashMap<>();
            try {
                Map<String, String> requestHeaders = request.getHeaders();
                if (requestHeaders != null) {
                    this.headers.putAll(requestHeaders);
                }
            } catch (AuthFailureError e) {
                Log.d(TAG, "Unable to fetch request headers for message signing " + e);
            }
            if (headers != null) {
                this.headers.putAll(headers);
            }
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
                Log.d(TAG, "Unable to fetch request body for message signing " + e);
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

        @Override
        public String getAuthority() {
            return javaUri.getHost();
        }

        @Override
        public String getScheme() {
            return javaUri.getScheme();
        }

        @Override
        public String getTargetUri() {
            return javaUri.toString();
        }

        @Override
        public String getRequestTarget() {
            String requestTarget = "";
            if (javaUri.getRawPath() != null) {
                requestTarget += javaUri.getRawPath();
            }
            if (javaUri.getRawQuery() != null) {
                requestTarget += "?" + javaUri.getRawQuery();
            }
            return requestTarget;
        }

        @Override
        public String getPath() {
            String rawPath = javaUri.getRawPath();
            return rawPath == null ? "" : rawPath;
        }

        @Override
        public String getQuery() {
            return javaUri.getRawQuery();
        }

        @Override
        public String getQueryParam(String name) {
            List<String> values = androidUri.getQueryParameters(name);
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
