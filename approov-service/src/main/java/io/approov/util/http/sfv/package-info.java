/**
 * Implementation of <a href= "https://www.rfc-editor.org/rfc/rfc8941.html">IETF
 * RFC 8941: Structured Field Values for HTTP</a>, including the
 * <a href= "https://www.rfc-editor.org/rfc/rfc9651.html">RFC 9651</a> Date and
 * Display String additions.
 * <p>
 * This package is adapted from the Apache-2.0 licensed
 * <a href="https://github.com/reschke/structured-fields">reschke/structured-fields</a>
 * project (see the LICENSE file in this directory and the repository README for the
 * upstream revision). Modifications from upstream: the package was renamed, the
 * encoding helpers use android.util.Base64, and the java.util.function based APIs were
 * replaced or removed because the library supports Android API levels that predate
 * them.
 * <p>
 * Includes a {@link io.approov.util.http.sfv.Parser} and object equivalents of the defined data types
 * (see {@link io.approov.util.http.sfv.Type}).
 * <p>
 * Here's a minimal example:
 * 
 * <pre><code>
 * {
 *     Parser p = new Parser("a=?0, b, c; foo=bar");
 *     Dictionary d = p.parseDictionary();
 *     for (Map.Entry&lt;String, Item&lt;? extends Object&gt;&gt; e : d.get()) {
 *         String key = e.getKey();
 *         Item&lt;? extends Object&gt; item = e.getValue();
 *         Object value = item.get();
 *         Parameters params = item.getParams();
 *         System.out.println(key + " -&gt; " + value + (params.isEmpty() ? "" : (" (" + params.serialize() + ")")));
 *     }
 * }
 * </code></pre>
 * <p>
 * gives:
 * 
 * <pre>
 * a -&gt; false
 * b -&gt; true
 * c -&gt; true (;foo=bar)
 * </pre>
 */

package io.approov.util.http.sfv;
