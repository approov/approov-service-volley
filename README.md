# Approov Service for Volley

A wrapper for the [Approov SDK](https://github.com/approov/approov-android-sdk) to enable easy integration when using [`Volley`](https://developer.android.com/training/volley) for making the API calls that you wish to protect with Approov. In order to use this you will need a trial or paid [Approov](https://www.approov.io) account.

## Adding ApproovService Dependency
The Approov integration is available via [`jitpack`](https://jitpack.io). This allows inclusion into the project by simply specifying a dependency in the `gradle` files for the app.

Firstly, `jitpack` needs to be added to the end the `repositories` section in the `build.gradle` file at the top root level of the project:

```
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

Secondly, add the dependency in your app's `build.gradle`:

```
dependencies {
	implementation 'com.github.approov:approov-service-volley:2.7.0'
}
```

This package is actually an open source wrapper layer that allows you to easily use Approov with `Volley`. This has a further dependency to the closed source [Approov SDK](https://github.com/approov/approov-android-sdk).

## Using ApproovService
In order to use the `ApproovService` you should create a `VolleyService` class:

```Java
import io.approov.service.volley.ApproovService;

public class VolleyService {
    private static Context appContext;
    private static ApproovService approovService;
    private static RequestQueue requestQueue;

    public static synchronized void initialize(Context context) {
        appContext = context;
        approovService = new ApproovService(appContext, "<enter-your-config-string-here>")
    }

    public static synchronized RequestQueue getRequestQueue() {
        if (requestQueue == null) {
            requestQueue = Volley.newRequestQueue(appContext, approovService.getBaseHttpStack());
        }
        return requestQueue;
    }
}
```

The `<enter-your-config-string-here>` is a custom string that configures your Approov account access. Obtain this using the `approov` CLI tool (see [installation instructions](https://approov.io/docs/latest/approov-installation/)):

```
approov sdk -getConfigString
```
This will output a configuration string, something like `#123456#K/XPlLtfcwnWkzv99Wj5VmAxo4CrU267J1KlQyoz8Qo=`, that will identify your Approov account. Use this instead of the text `<enter-your-config-string-here>`.

You must initialize this when your app is created, usually in the `onCreate` method:

```Java
public class YourApp extends Application {
    public static ApproovService approovService;

    @Override
    public void onCreate() {
        super.onCreate();
        VolleyService.initialize(getApplicationContext());
    }
}
```

You can then make Approov enabled `Volley` API calls by using the `RequestQueue` available from the `VolleyService`:

```Java
VolleyService.getRequestQueue().add(request);
```

This uses the `ApproovService` base `http` stack to include an interceptor to add the `Approov-Token` header and pins the connections.

## Manifest Changes

The following app permissions need to be available in the manifest to use Approov:

```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.INTERNET" />
```

Note that the minimum SDK version you can use with the Approov package is 21 (Android 5.0). 

Please [read this](https://approov.io/docs/latest/approov-usage-documentation/#targetting-android-11-and-above) section of the reference documentation if targetting Android 11 (API level 30) or above.

## Discovery Mode

If you are performing a quick assessment of the environments that you app is running in, and also if there are any requests being made that are not emanating from your apps, then you can use discovery mode. This is a minimal implementation of Approov that doesn't automatically check Approov tokens at the backend. Requesting the Approov tokens in your apps gathers metrics. Once you have pushed the version of the app using Approov to all of your users you can do an informal check using logs of your backend requests to see if there are any requests that are not presenting an Approov token.

Setting up Approov to work in this way is extremely simple. You must enabled the wildcard option on your account as follows:

```
approov api -setWildcardMode on
```

This ensures that Approov will provide an Approov token for every API request being made, without having to specifically add API domains. The Approov token will be added as an `Approov-Token` header for all requests that are made via an `ApproovService` created `VolleyService`.

These Approov tokens will not be valid are are simply provided to assess if they are reaching your backend API or not. Since they are not valid they do not need to be protected via pinning and thus none is applied by Approov. Furthermore, if you are only performing discovery you do not need to register your apps.

It is possible to see the properties of all of your running apps using [metrics graphs](https://approov.io/docs/latest/approov-usage-documentation/#metrics-graphs). You can also [assess the validity](https://approov.io/docs/latest/approov-usage-documentation/#checking-token-validity) of individual Approov tokens if required.

Remember to [switch](https://approov.io/docs/latest/approov-usage-documentation/#setting-wildcard-mode) to `off` again before completing a full Approov integration.

## Approov Token Header
The default header name of `Approov-Token` can be changed as follows:

```Java
approovService.setApproovHeader("Authorization", "Bearer ")
```

The first parameter is the new header name and the second a prefix to be added to the Approov token. This is primarily for integrations where the Approov Token JWT might need to be prefixed with `Bearer` and passed in the `Authorization` header.

## Token Binding
If you are using [Token Binding](https://approov.io/docs/latest/approov-usage-documentation/#token-binding) then set the header holding the value to be used for binding as follows:

```Java
approovService.setBindingHeader("Authorization")
```

In this case it means that the value of `Authorization` holds the token value to be bound. This only needs to be called once. On subsequent requests the value of the specified header is read and its value set as the token binding value. Note that if the header is not present on a request then the value `NONE` is used. Note that you should only select a header that is normally always present and the value does not typically change from request to request, as each change requires a new Approov token to be fetched.

## Token Prefetching
If you wish to reduce the latency associated with fetching the first Approov token, then make this call immediately after creating `ApproovService`:

```Java
approovService.prefetchApproovToken()
```

This initiates the process of fetching an Approov token as a background task, so that a cached token is available immediately when subsequently needed, or at least the fetch time is reduced. Note that there is no point in performing a prefetch if you are using token binding.

## Configuration Persistence
An Approov app automatically downloads any new configurations of APIs and their pins that are available. These are stored in the [`SharedPreferences`](https://developer.android.com/reference/android/content/SharedPreferences) for the app in a preference file `approov-prefs` and key `approov-config`. You can store the preferences differently by modifying or overriding the methods `ApproovService.putApproovDynamicConfig` and `ApproovService.getApproovDynamicConfig`.
