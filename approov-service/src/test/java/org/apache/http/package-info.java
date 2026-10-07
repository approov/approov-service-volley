/**
 * Minimal stand-ins for the legacy Apache HttpClient types referenced by the signatures
 * of Volley's deprecated {@code HttpStack}/{@code BaseHttpStack#performRequest} methods.
 * Plain JVM unit tests need these on the classpath purely so class loading and
 * verification succeed; no test actually invokes the deprecated request paths, which is
 * why only the members required for linkage are declared.
 * <p>
 * Do not extend these stubs with behavior. If a test ever needs working Apache HTTP
 * classes, depend on {@code org.apache.httpcomponents:httpclient} instead, and note that
 * under Robolectric these classes may shadow the android-all bundled copies.
 */
package org.apache.http;
