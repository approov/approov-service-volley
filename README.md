# Approov Service for Volley

![Java](https://img.shields.io/badge/Java-8%2B-007396?logo=openjdk&logoColor=white)
![Android](https://img.shields.io/badge/Android-minSdk%2023-3DDC84?logo=android&logoColor=white)
![Maven Central](https://img.shields.io/maven-central/v/io.approov/service.volley?logo=apachemaven&logoColor=white&label=Maven%20Central)
![Message Signing](https://img.shields.io/badge/Message%20Signing-RFC%209421-1f6feb)
![Build](https://github.com/approov/approov-service-volley/actions/workflows/build_and_test.yml/badge.svg)

A wrapper for the [Approov SDK](https://github.com/approov/approov-android-sdk) to enable easy integration when using [`Volley`](https://developer.android.com/training/volley) for making the API calls that you wish to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

This page provides the steps for integrating Approov into your app. To follow this guide you should have received an onboarding email for a trial or paid Approov account.

## ADDING APPROOV SERVICE DEPENDENCY

The Approov integration is available via [`mavenCentral`](https://mvnrepository.com/repos/central). This allows inclusion into the project by simply specifying a dependency in the `gradle` files for the app.

The `mavenCentral()` repository is already present in the build.gradle file so the only import you need to make is the actual service layer itself:

```groovy
implementation("io.approov:service.volley:3.5.5")
```

Make sure you do a Gradle sync (by selecting `Sync Now` in the banner at the top of the modified `.gradle` file) after making these changes.

This package is actually an open source wrapper layer that allows you to easily use Approov with `Volley`. This has a further dependency to the closed source [Approov SDK](https://central.sonatype.com/artifact/io.approov/approov-android-sdk/3.5.3). In some cases you may need to also add this implementation to your dependencies list to avoid build errors:

```groovy
implementation("io.approov:approov-android-sdk:3.5.3")
```

## MANIFEST CHANGES

The following app permissions need to be available in the manifest to use Approov:

```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.INTERNET" />
```

Note that the minimum SDK version you can use with the Approov package is 23 (Android 6.0). 

Please [read this](https://approov.io/docs/latest/approov-usage-documentation/#targeting-android-11-and-above) section of the reference documentation if targeting Android 11 (API level 30) or above.

## INITIALIZING APPROOV SERVICE

In order to use the `ApproovService` you must initialize it when your app is created, usually in the `onCreate` method:

Initialization can fail (bad config, SDK error), so wrap it in a `try/catch` and make sure your app survives a failure rather than crashing:

### Java
```java
import android.util.Log;
import io.approov.service.volley.ApproovService;
import java.util.UUID;

public class YourApp extends Application {
    private static final String TAG = "YourApp";

    @Override
    public void onCreate() {
        super.onCreate();

        // An app-generated id used to correlate this install/session across your own app
        // logs and your backend. Use a UUID, or any session/user identifier you already
        // have — it is NOT an Approov secret.
        String correlationId = UUID.randomUUID().toString();

        try {
            ApproovService.initialize(getApplicationContext(), "<enter-your-config-string-here>");
            // Confirm Approov is actually active before treating it as enabled, then log
            // identifiers for correlation / observability.
            if (ApproovService.isApproovEnabled()) {
                Log.i(TAG, "Approov initialized; deviceID=" + ApproovService.getDeviceID()
                        + " session=" + correlationId);
            } else {
                Log.w(TAG, "Approov initialized in bypass mode (no protection); session=" + correlationId);
            }
        } catch (Exception e) {
            // Initialization failed — log it and continue UNPROTECTED so the app still works.
            // Re-initializing with an empty config string enters bypass mode (initialized, but
            // no Approov token injection, pinning, or secret substitution).
            Log.e(TAG, "Approov init failed (session=" + correlationId + "); continuing unprotected", e);
            ApproovService.initialize(getApplicationContext(), "");
        }
    }
}
```

### Kotlin
```kotlin
import android.util.Log
import io.approov.service.volley.ApproovService
import java.util.UUID

class YourApp : Application() {
    private val TAG = "YourApp"

    override fun onCreate() {
        super.onCreate()

        // An app-generated id used to correlate this install/session across your own app logs
        // and your backend. Use a UUID, or any session/user identifier — it is NOT an Approov secret.
        val correlationId = UUID.randomUUID().toString()

        try {
            ApproovService.initialize(applicationContext, "<enter-your-config-string-here>")
            if (ApproovService.isApproovEnabled()) {
                Log.i(TAG, "Approov initialized; deviceID=${ApproovService.getDeviceID()} session=$correlationId")
            } else {
                Log.w(TAG, "Approov initialized in bypass mode (no protection); session=$correlationId")
            }
        } catch (e: Exception) {
            // Initialization failed — continue UNPROTECTED (bypass mode) instead of crashing.
            Log.e(TAG, "Approov init failed (session=$correlationId); continuing unprotected", e)
            ApproovService.initialize(applicationContext, "")
        }
    }
}
```

The `<enter-your-config-string-here>` is a custom string that configures your Approov account access. This will have been provided in your Approov onboarding email.

On success the example logs the Approov **device ID** (`getDeviceID()`) and an **app-generated session/correlation id** (a UUID, or any session/user identifier you use) so a given install can be correlated across your app logs, backend, and the Approov [Live Metrics](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). If initialization fails, the example re-initializes with an empty config so the app keeps working — but those requests go out **without Approov protection**, so treat the backend as the enforcement point.

## USING APPROOV SERVICE

You can then make Approov enabled `Volley` API calls by using the `RequestQueue` constructed with the Approov base HTTP stack:

### Java
```java
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.Volley;
import io.approov.service.volley.ApproovService;

RequestQueue queue = Volley.newRequestQueue(context, ApproovService.getBaseHttpStack());
```

### Kotlin
```kotlin
import com.android.volley.toolbox.Volley
import io.approov.service.volley.ApproovService

val queue = Volley.newRequestQueue(context, ApproovService.getBaseHttpStack())
```

This uses the `ApproovService` base `http` stack to include an interceptor that protects channel integrity (with either pinning or managed trust roots). The interceptor also adds the `Approov-Token` header and performs any dynamic secret substitutions. You should thus use this queue for all API calls you may wish to protect.

Approov errors will generate an `ApproovException`, which is a type of Volley `AuthFailureError`. This may be further specialized into an `ApproovNetworkException`, indicating an issue with networking that should provide an option for a user-initiated retry.

## CHECKING IT WORKS

Initially you won't have set which API domains to protect, so the interceptor will not add anything. It will have called Approov though and made contact with the Approov cloud service. You will see logging from Approov saying `UNKNOWN_URL`.

Your Approov onboarding email should contain a link allowing you to access [Live Metrics Graphs](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). After you've run your app with Approov integration you should be able to see the results in the live metrics within a minute or so. At this stage you could even release your app to get details of your app population and the attributes of the devices they are running upon.

## NEXT STEPS

To actually protect your APIs and/or secrets there are some further steps. Approov provides two different options for protection:

* **API PROTECTION**: You should use this if you control the backend API(s) being protected and are able to modify them to ensure that a valid Approov token is being passed by the app. An [Approov Token](https://approov.io/docs/latest/approov-usage-documentation/#approov-tokens) is short lived cryptographically signed JWT proving the authenticity of the call.

* **SECRETS PROTECTION**: This allows app secrets, including API keys for 3rd party services, to be protected so that they no longer need to be included in the released app code. These secrets are only made available to valid apps at runtime.

Note that it is possible to use both approaches side-by-side in the same app.

---

## Useful Links

- [Approov SDK](https://github.com/approov/approov-android-sdk)
- [Volley Documentation](https://developer.android.com/training/volley)
- [Approov Website](https://www.approov.io)
- [Reference Documentation](REFERENCE.md)
- [Usage Guide](USAGE.md)
- [Changelog](CHANGELOG.md)

## Included 3rd party Source

To support message signing, this repo has adapted code released by two 3rd
party developers. The LICENSE files have been copied from the repos into the
associated directories listed below:

* `approov-service/src/main/java/io/approov/util/http/sfv`
    * Repo: https://github.com/reschke/structured-fields
    * Commit hash: d43f2ad6c655b92a7ef52aafa763418e1c6fed78
    * License: Apache V2
* `approov-service/src/main/java/io/approov/util/sig`
    * Repo: https://github.com/bspk/httpsig-java
    * Commit hash: ffe86ae1d07425f13b018329f51c7a7c0833d71f
    * License: MIT
