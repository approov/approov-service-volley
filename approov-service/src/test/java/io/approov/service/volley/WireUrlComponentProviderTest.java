package io.approov.service.volley;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.android.volley.Request;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.net.URI;
import java.util.LinkedHashMap;

/**
 * The derived components of a signed request come from the URL in the form Android sends it, parsed with
 * OkHttp's HttpUrl: {@code @target-uri} is that URL without the fragment, which is never sent, and without an
 * explicit default port, and {@code @authority} is the lowercase host with a non-default port. Nothing is
 * parsed with {@code java.net.URI}, which encodes {@code |} in the query as {@code %7C} and rejects some
 * queries that Android sends.
 */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class WireUrlComponentProviderTest {

    private static ApproovDefaultMessageSigning.VolleyComponentProvider provider(String url) {
        return new ApproovDefaultMessageSigning.VolleyComponentProvider(
                ApproovTestSupport.request(Request.Method.GET, url, new LinkedHashMap<String, String>(), null, null),
                new LinkedHashMap<String, String>());
    }

    @Test
    public void targetUriIsTheUrlTheStackSendsForPipeQueries() {
        String url = "https://maps.example.com/api/staticmap?path=color:red|weight:5&markers=a|b";
        ApproovDefaultMessageSigning.VolleyComponentProvider p = provider(url);
        assertEquals(url, p.getTargetUri());
        assertEquals("/api/staticmap?path=color:red|weight:5&markers=a|b", p.getRequestTarget());
    }

    @Test
    public void targetUriKeepsTheEncodingOfSpacesPercentAndNonAscii() {
        String wire = "https://example.com/caf%C3%A9/a%2Fb?q=a%20b&pct=100%25&name=caf%C3%A9&pipe=x|y&plus=a+b";
        ApproovDefaultMessageSigning.VolleyComponentProvider p = provider(wire);
        assertEquals(wire, p.getTargetUri());
        assertEquals("https", p.getScheme());
        assertEquals("example.com", p.getAuthority());
        assertEquals("/caf%C3%A9/a%2Fb", p.getPath());
        assertEquals("/caf%C3%A9/a%2Fb?q=a%20b&pct=100%25&name=caf%C3%A9&pipe=x|y&plus=a+b", p.getRequestTarget());
    }

    @Test
    public void targetUriForAUrlJavaNetUriRejects() {
        String url = "https://example.com/s?f={%22a%22:1}&c=^`&p=x|y";
        try {
            URI.create(url);
            fail("java.net.URI is expected to reject this URL, which the stack sends as is");
        } catch (IllegalArgumentException expected) {
            // the reason the layer must never parse the request URL with java.net.URI
        }
        ApproovDefaultMessageSigning.VolleyComponentProvider p = provider(url);
        assertEquals(url, p.getTargetUri());
        assertEquals("/s?f={%22a%22:1}&c=^`&p=x|y", p.getRequestTarget());
    }

    @Test
    public void targetUriLeavesOutTheFragmentWhichIsNeverSent() {
        ApproovDefaultMessageSigning.VolleyComponentProvider p = provider("https://example.com/p?x=1|2#frag|ment");
        assertEquals("https://example.com/p?x=1|2", p.getTargetUri());
        assertEquals("/p?x=1|2", p.getRequestTarget());
        assertEquals("https://example.com/p%2Fx?q=a%20b", provider("https://example.com/p%2Fx?q=a%20b#f").getTargetUri());
    }

    @Test
    public void targetUriLeavesOutAnExplicitDefaultPortOnly() {
        assertEquals("https://host/p?a=1", provider("https://host:443/p?a=1").getTargetUri());
        assertEquals("http://host/p", provider("http://host:80/p").getTargetUri());
        assertEquals("https://host:8443/p", provider("https://host:8443/p").getTargetUri());
        assertEquals("http://host:443/p", provider("http://host:443/p").getTargetUri());
        assertEquals("https://host:80/p", provider("https://host:80/p").getTargetUri());
        // the scheme is compared without regard to case, and Android sends it in lowercase
        assertEquals("https://host/p", provider("HTTPS://host:443/p").getTargetUri());
        // a URL with no path or no query
        assertEquals("https://host/", provider("https://host:443/").getTargetUri());
        assertEquals("https://host/?a=1", provider("https://host:443/?a=1#f").getTargetUri());
        assertEquals("https://host/p?", provider("https://host:443/p?").getTargetUri());
        // user info and an IPv6 host
        assertEquals("https://user:pw@host/p", provider("https://user:pw@host:443/p").getTargetUri());
        assertEquals("https://[::1]/p", provider("https://[::1]:443/p").getTargetUri());
        assertEquals("https://[::1]:8443/p", provider("https://[::1]:8443/p").getTargetUri());
        assertEquals("https://[::1]/p", provider("https://[::1]/p").getTargetUri());
        // a colon in the path or query is never taken for a port
        assertEquals("https://host/a:443/b?x=:443", provider("https://host/a:443/b?x=:443").getTargetUri());
    }

    @Test
    public void targetUriOfAUrlWithNoPathHasTheRootPathTheStackSends() {
        assertEquals("https://example.com/", provider("https://example.com").getTargetUri());
        assertEquals("https://example.com/?a=1", provider("https://example.com?a=1").getTargetUri());
        assertEquals("/", provider("https://example.com").getPath());
    }

    @Test
    public void authorityHasTheLowercaseHostAndTheNonDefaultPortOnly() {
        assertEquals("example.com:8443", provider("https://Example.com:8443/").getAuthority());
        assertEquals("example.com", provider("https://example.com:443/").getAuthority());
        assertEquals("example.com", provider("http://example.com:80/").getAuthority());
        assertEquals("example.com:443", provider("http://example.com:443/").getAuthority());
        assertEquals("example.com:80", provider("https://example.com:80/").getAuthority());
        assertEquals("[::1]:8080", provider("http://[::1]:8080/").getAuthority());
        assertEquals("[::1]", provider("https://[::1]/").getAuthority());
        assertEquals("example.com", provider("https://user:pw@EXAMPLE.com/").getAuthority());
    }

    @Test
    public void aUrlThatCannotBeParsedFailsTheComponentNotTheProvider() {
        // the provider is built for any request, and only the component that needs the URL fails
        ApproovDefaultMessageSigning.VolleyComponentProvider p = provider("not a url");
        try {
            p.getTargetUri();
            fail("a URL that cannot be parsed has no target URI");
        } catch (RuntimeException expected) {
            // inside the fail-open of the signer
        }
    }
}
