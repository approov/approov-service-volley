package android.util;

import java.nio.charset.StandardCharsets;

/**
 * Minimal stand-in for the Android framework Base64 so library code can run in plain
 * JVM unit tests, where android.jar only provides stubbed methods. It mirrors the
 * Android semantics for the flags used here: line wrapping with a trailing separator
 * by default, NO_WRAP, NO_PADDING, CRLF and URL_SAFE, and a decoder that is lenient
 * about whitespace and missing padding.
 * <p>
 * Note for Robolectric-based tests this class may shadow the real framework
 * implementation, so it must stay behaviorally compatible and provide the overloads
 * the framework offers for the operations used in tests.
 */
public final class Base64 {
    public static final int DEFAULT = 0;
    public static final int NO_PADDING = 1;
    public static final int NO_WRAP = 2;
    public static final int CRLF = 4;
    public static final int URL_SAFE = 8;
    public static final int NO_CLOSE = 16;

    private static final int LINE_LENGTH = 76;

    private Base64() {
    }

    public static byte[] decode(String input, int flags) {
        return decode(input.getBytes(StandardCharsets.US_ASCII), flags);
    }

    public static byte[] decode(byte[] input, int flags) {
        return decode(input, 0, input.length, flags);
    }

    public static byte[] decode(byte[] input, int offset, int len, int flags) {
        // the Android decoder skips whitespace and accepts missing padding
        StringBuilder stripped = new StringBuilder(len);
        for (int i = offset; i < offset + len; i++) {
            char c = (char) (input[i] & 0xff);
            if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
                stripped.append(c);
            }
        }
        String text = stripped.toString();
        int padding = (4 - text.length() % 4) % 4;
        if ((padding == 1 || padding == 2) && !text.endsWith("=")) {
            text += padding == 1 ? "=" : "==";
        }
        java.util.Base64.Decoder decoder = (flags & URL_SAFE) != 0
                ? java.util.Base64.getUrlDecoder()
                : java.util.Base64.getDecoder();
        return decoder.decode(text);
    }

    public static String encodeToString(byte[] input, int flags) {
        return new String(encode(input, flags), StandardCharsets.US_ASCII);
    }

    public static byte[] encode(byte[] input, int flags) {
        java.util.Base64.Encoder encoder = (flags & URL_SAFE) != 0
                ? java.util.Base64.getUrlEncoder()
                : java.util.Base64.getEncoder();
        if ((flags & NO_PADDING) != 0) {
            encoder = encoder.withoutPadding();
        }
        String encoded = encoder.encodeToString(input);
        if ((flags & NO_WRAP) != 0) {
            return encoded.getBytes(StandardCharsets.US_ASCII);
        }
        // the Android encoder wraps lines and appends a final line separator by default
        String separator = (flags & CRLF) != 0 ? "\r\n" : "\n";
        StringBuilder wrapped = new StringBuilder(encoded.length() + encoded.length() / LINE_LENGTH * 2 + 2);
        for (int i = 0; i < encoded.length(); i += LINE_LENGTH) {
            wrapped.append(encoded, i, Math.min(i + LINE_LENGTH, encoded.length()));
            wrapped.append(separator);
        }
        return wrapped.toString().getBytes(StandardCharsets.US_ASCII);
    }
}
