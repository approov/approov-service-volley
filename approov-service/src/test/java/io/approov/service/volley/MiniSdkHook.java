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

import com.criticalblue.approovsdk.Approov;
import com.criticalblue.approovsdk.MiniSdkCallHook;
import com.criticalblue.minisdk.testing.AttesterProxyController;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A mini-SDK call hook that records every call the layer makes to the Approov SDK and can answer the token
 * fetch, the secure string fetch and the pin set in place of the mini-SDK, so that a test chooses the
 * status of each fetch. Anything it does not answer runs in the mini-SDK.
 */
class MiniSdkHook implements MiniSdkCallHook {
    // every call in order, as "method" or "method:argument"
    final List<String> calls = Collections.synchronizedList(new ArrayList<>());

    // the answer to a token fetch for a URL, or null to let the mini-SDK answer
    volatile TokenAnswer tokenAnswer;

    // the secure string results by key, consulted before the mini-SDK
    final Map<String, Approov.TokenFetchResult> secureStrings = Collections.synchronizedMap(new HashMap<>());

    // the pin set the SDK reports, or null to let the mini-SDK answer
    volatile Map<String, List<String>> pins;

    // the answer to a pin set read, consulted before pins, which may return null or throw as the SDK might
    volatile PinsAnswer pinsAnswer;

    // the answer to a pin set read
    interface PinsAnswer {
        Map<String, List<String>> pins();
    }

    // the answer to a token fetch
    interface TokenAnswer {
        Approov.TokenFetchResult fetch(String url);
    }

    static <T extends MiniSdkHook> T install(T hook) {
        AttesterProxyController.setCallHook(hook);
        return hook;
    }

    static void uninstall() {
        AttesterProxyController.setCallHook(null);
    }

    List<String> snapshot() {
        synchronized (calls) {
            return new ArrayList<>(calls);
        }
    }

    // counts the calls of a method, with any argument
    int count(String method) {
        int n = 0;
        for (String call : snapshot()) {
            if (call.equals(method) || call.startsWith(method + ":"))
                n++;
        }
        return n;
    }

    // answers every token fetch with the given status, token and trace ID
    void answerTokens(Approov.TokenFetchStatus status, String token, String traceID) {
        tokenAnswer = url -> result(status, token, traceID, null);
    }

    // lists the hosts as Approov API domains with no pins of their own
    void listHosts(String... hosts) {
        Map<String, List<String>> map = new HashMap<>();
        for (String host : hosts)
            map.put(host, new ArrayList<>());
        pins = map;
    }

    @Override
    public Object onCall(String method, Object[] args, Call sdk) {
        switch (method) {
            case "fetchApproovTokenAndWait": {
                String url = (String) args[0];
                calls.add(method + ":" + url);
                TokenAnswer answer = tokenAnswer;
                return (answer != null) ? answer.fetch(url) : sdk.proceed(args);
            }
            case "fetchSecureStringAndWait": {
                String key = (String) args[0];
                calls.add(method + ":" + key);
                Approov.TokenFetchResult answer = secureStrings.get(key);
                return (answer != null) ? answer : sdk.proceed(args);
            }
            case "getPins": {
                calls.add(method + ":" + args[0]);
                PinsAnswer pinsAnswer = this.pinsAnswer;
                if (pinsAnswer != null)
                    return pinsAnswer.pins();
                Map<String, List<String>> answer = pins;
                return (answer != null) ? answer : sdk.proceed(args);
            }
            case "setDataHashInToken":
                calls.add(method + ":" + args[0]);
                return sdk.proceed(args);
            default:
                calls.add(method);
                return sdk.proceed(args);
        }
    }

    /**
     * Builds a fetch result as the SDK builds it.
     *
     * @param status is the fetch status
     * @param token is the token, or null for none
     * @param traceID is the trace ID, or null for none
     * @param secureString is the secure string, or null for none
     * @return the fetch result
     */
    static Approov.TokenFetchResult result(Approov.TokenFetchStatus status, String token, String traceID,
            String secureString) {
        try {
            java.lang.reflect.Constructor<Approov.TokenFetchResult> constructor =
                    Approov.TokenFetchResult.class.getDeclaredConstructor(Approov.TokenFetchStatus.class,
                            String.class, String.class, String.class, String.class, String.class,
                            boolean.class, boolean.class, byte[].class);
            constructor.setAccessible(true);
            return constructor.newInstance(status, token, traceID, secureString, "ARC-" + status.name(), "",
                    false, false, null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("the mini-SDK TokenFetchResult constructor changed", e);
        }
    }

    // a secure string fetch result
    static Approov.TokenFetchResult secureString(Approov.TokenFetchStatus status, String value) {
        return result(status, null, null, value);
    }
}
