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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.ExecutorDelivery;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.BaseHttpStack;
import com.android.volley.toolbox.BasicNetwork;
import com.android.volley.toolbox.NoCache;
import com.criticalblue.approovsdk.Approov;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import okhttp3.mockwebserver.RecordedRequest;

/**
 * The stack from getBaseHttpStack() is always available. Before protection is enabled, which is before initialize
 * and in bypass mode, it sends requests untouched. It is one instance for the life of the process, so the stack
 * an app holds, or a queue built on it, protects requests once initialize enables protection.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class StackBeforeInitialize370Test {
    private MiniSdkHttpsOrigins origins;

    @Before
    public void setUp() throws Exception {
        ApproovService.reset();
        origins = new MiniSdkHttpsOrigins(true);
    }

    @After
    public void tearDown() throws Exception {
        origins.shutdown();
    }

    private RecordedRequest sendThrough(BaseHttpStack stack) throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        stack.executeRequest(new MiniSdkHttpsOrigins.AppRequest(origins.firstUrl("/path"))
                .header("X-App", "kept"), java.util.Collections.<String, String>emptyMap()).getContent().close();
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull("not delivered", recorded);
        assertEquals("kept", recorded.getHeader("X-App"));
        return recorded;
    }

    private MiniSdkHook initializeProtected() {
        MiniSdkHook sdk = origins.initialize(new MiniSdkHook());
        sdk.listHosts("localhost");
        sdk.answerTokens(Approov.TokenFetchStatus.SUCCESS, "jwt-token", "trace-1");
        return sdk;
    }

    @Test
    public void theStackBeforeInitializeIsNotNullAndSendsUntouched() throws Exception {
        BaseHttpStack stack = ApproovService.getBaseHttpStack();
        assertNotNull(stack);
        assertTrue(stack instanceof ApproovHurlStack);
        MiniSdkHttpsOrigins.assertNoApproovHeaders("before initialize", sendThrough(stack));
    }

    @Test
    public void theSameInstanceAddsTheTokenAfterInitialize() throws Exception {
        BaseHttpStack before = ApproovService.getBaseHttpStack();
        assertNotNull(before);
        MiniSdkHttpsOrigins.assertNoApproovHeaders("before initialize", sendThrough(before));

        initializeProtected();

        assertSame(before, ApproovService.getBaseHttpStack());
        assertEquals("jwt-token", sendThrough(before).getHeader("Approov-Token"));
    }

    @Test
    public void theStackInBypassModeSendsUntouched() throws Exception {
        ApproovService.initialize(origins.context, "");
        assertTrue(ApproovService.isApproovServiceEnabled());
        assertFalse(ApproovService.isApproovProtectionEnabled());
        BaseHttpStack stack = ApproovService.getBaseHttpStack();
        assertNotNull(stack);
        MiniSdkHttpsOrigins.assertNoApproovHeaders("bypass", sendThrough(stack));
    }

    @Test
    public void aQueueBuiltBeforeInitializeIsProtectedAfterIt() throws Exception {
        RequestQueue queue = new RequestQueue(new NoCache(), new BasicNetwork(ApproovService.getBaseHttpStack()), 1,
                new ExecutorDelivery(Runnable::run));
        queue.start();
        try {
            MiniSdkHttpsOrigins.assertNoApproovHeaders("before initialize", viaQueue(queue));
            initializeProtected();
            assertEquals("jwt-token", viaQueue(queue).getHeader("Approov-Token"));
        } finally {
            queue.stop();
        }
    }

    private RecordedRequest viaQueue(RequestQueue queue) throws Exception {
        origins.first.enqueue(MiniSdkHttpsOrigins.ok());
        final CountDownLatch done = new CountDownLatch(1);
        queue.add(new com.android.volley.toolbox.StringRequest(origins.firstUrl("/queued"),
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        done.countDown();
                    }
                }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        done.countDown();
                    }
                }));
        assertTrue("queue did not answer", done.await(10, TimeUnit.SECONDS));
        RecordedRequest recorded = origins.take(origins.first);
        assertNotNull("not delivered", recorded);
        return recorded;
    }
}
