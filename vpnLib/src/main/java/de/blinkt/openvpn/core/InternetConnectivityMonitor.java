// ========================================
// 1. Create new file: InternetConnectivityMonitor.java
// Location: android/app/src/main/java/de/blinkt/openvpn/core/
// ========================================

package de.blinkt.openvpn.core;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import de.blinkt.openvpn.R;

/**
 * Monitors internet connectivity when VPN is connected and app is killed
 * Sends notifications when internet is lost or restored
 */
public class InternetConnectivityMonitor {

    private static final String TAG = "InternetMonitor";
    private static final String NOTIFICATION_CHANNEL_ID = "vpn_internet_monitor";
    private static final int NO_INTERNET_NOTIFICATION_ID = 88888;
    private static final int INTERNET_RESTORED_NOTIFICATION_ID = 88889;
    private static final long NOTIFICATION_COOLDOWN_MS = 60000; // 1 minute
    private static final long CONNECTIVITY_CHECK_DELAY_MS = 5000; // 5 seconds

    private final Context context;
    private final ConnectivityManager connectivityManager;
    private final NotificationManager notificationManager;
    private final Handler handler;

    private NetworkCallback networkCallback;
    private boolean isMonitoring = false;
    private boolean hasInternet = true;
    private long lastNotificationTime = 0;

    public InternetConnectivityMonitor(Context context) {
        this.context = context.getApplicationContext();
        this.connectivityManager = (ConnectivityManager)
            context.getSystemService(Context.CONNECTIVITY_SERVICE);
        this.notificationManager = (NotificationManager)
            context.getSystemService(Context.NOTIFICATION_SERVICE);
        this.handler = new Handler(Looper.getMainLooper());

        createNotificationChannel();
    }

    /**
     * Start monitoring internet connectivity
     */
    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    public void startMonitoring() {
        if (isMonitoring) {
            Log.d(TAG, "🌐 Internet monitor already running");
            return;
        }

        Log.d(TAG, "🌐 Starting internet connectivity monitoring");

        networkCallback = new NetworkCallback();

        NetworkRequest networkRequest = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                .build();

        connectivityManager.registerNetworkCallback(networkRequest, networkCallback);
        isMonitoring = true;

        // Initial connectivity check
        checkInternetConnectivity();

        Log.d(TAG, "✅ Internet monitoring started");
    }

    /**
     * Stop monitoring internet connectivity
     */
    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    public void stopMonitoring() {
        if (!isMonitoring) {
            return;
        }

        Log.d(TAG, "🛑 Stopping internet connectivity monitoring");

        if (networkCallback != null) {
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback);
            } catch (Exception e) {
                Log.e(TAG, "Error unregistering network callback: " + e.getMessage());
            }
            networkCallback = null;
        }

        isMonitoring = false;
        hasInternet = true;

        // Remove any existing notifications
        notificationManager.cancel(NO_INTERNET_NOTIFICATION_ID);
        notificationManager.cancel(INTERNET_RESTORED_NOTIFICATION_ID);

        Log.d(TAG, "✅ Internet monitoring stopped");
    }

    /**
     * Network callback to monitor connectivity changes
     */
    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    private class NetworkCallback extends ConnectivityManager.NetworkCallback {

        @Override
        public void onAvailable(@NonNull Network network) {
            Log.d(TAG, "🌐 Network available: " + network);

            // Delay check to ensure network is actually usable
            handler.postDelayed(() -> {
                if (isMonitoring) {
                    checkInternetConnectivity();
                }
            }, CONNECTIVITY_CHECK_DELAY_MS);
        }

        @Override
        public void onLost(@NonNull Network network) {
            Log.d(TAG, "❌ Network lost: " + network);
            handleNoInternet();
        }

        @Override
        public void onCapabilitiesChanged(@NonNull Network network,
                                          @NonNull NetworkCapabilities networkCapabilities) {
            boolean hasInternet = networkCapabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                networkCapabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_VALIDATED);

            Log.d(TAG, "🌐 Network capabilities changed - Has Internet: " + hasInternet);

            if (!hasInternet) {
                handleNoInternet();
            } else {
                handleInternetRestored();
            }
        }
    }

    /**
     * Check actual internet connectivity by trying to reach a reliable server
     */
    private void checkInternetConnectivity() {
        new Thread(() -> {
            boolean internetAvailable = false;

            try {
                // Try to reach Google DNS
                URL url = new URL("https://www.google.com");
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestProperty("User-Agent", "Android");
                connection.setRequestProperty("Connection", "close");
                connection.setConnectTimeout(3000);
                connection.setReadTimeout(3000);
                connection.connect();

                internetAvailable = (connection.getResponseCode() == 200);
                connection.disconnect();

                Log.d(TAG, "✅ Internet connectivity check: " + internetAvailable);

            } catch (IOException e) {
                Log.d(TAG, "❌ Internet connectivity check failed: " + e.getMessage());
                internetAvailable = false;
            }

            final boolean finalResult = internetAvailable;
            handler.post(() -> {
                if (finalResult) {
                    handleInternetRestored();
                } else {
                    handleNoInternet();
                }
            });

        }).start();
    }

    /**
     * Handle no internet scenario
     */
    private void handleNoInternet() {
        if (!hasInternet) {
            return; // Already notified
        }

        Log.d(TAG, "❌ Internet connection LOST");
        hasInternet = false;

        // Check if app is alive
        if (isAppAlive()) {
            Log.d(TAG, "📱 App is alive - skipping notification");
            return;
        }

        // Check cooldown
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastNotificationTime < NOTIFICATION_COOLDOWN_MS) {
            Log.d(TAG, "⏳ Notification cooldown active");
            return;
        }

        showNoInternetNotification();
        lastNotificationTime = currentTime;
    }

    /**
     * Handle internet restored scenario
     */
    private void handleInternetRestored() {
        if (hasInternet) {
            return; // Already restored
        }

        Log.d(TAG, "✅ Internet connection RESTORED");
        hasInternet = true;

        // Remove no internet notification
        notificationManager.cancel(NO_INTERNET_NOTIFICATION_ID);

        // Check if app is alive
        if (isAppAlive()) {
            Log.d(TAG, "📱 App is alive - skipping notification");
            return;
        }

        showInternetRestoredNotification();
    }

    /**
     * Check if app is alive (in foreground or background but not killed)
     */
    private boolean isAppAlive() {
        try {
            SharedPreferences prefs = context.getSharedPreferences(
                "FlutterSharedPreferences", Context.MODE_PRIVATE);
            boolean isAlive = prefs.getBoolean("flutter.is_app_alive", false);
            Log.d(TAG, "App alive status: " + isAlive);
            return isAlive;
        } catch (Exception e) {
            Log.e(TAG, "Error checking app alive status: " + e.getMessage());
            return false;
        }
    }

    /**
     * Show no internet notification
     */
    private void showNoInternetNotification() {
        Log.d(TAG, "🔔 Showing no internet notification");

        Intent launchIntent = context.getPackageManager()
            .getLaunchIntentForPackage(context.getPackageName());

        if (launchIntent != null) {
            launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            launchIntent.putExtra("from_no_internet_notification", true);
            launchIntent.putExtra("notification_type", "no_internet");
        }

        PendingIntent pendingIntent = PendingIntent.getActivity(
            context,
            NO_INTERNET_NOTIFICATION_ID,
            launchIntent != null ? launchIntent : new Intent(),
            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Notification.Builder builder = new Notification.Builder(context)
            .setContentTitle("No Internet Connection")
            .setContentText("VPN is connected but there's no internet access. Check your connection.")
            .setSmallIcon(R.drawable.high)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setOngoing(false)
            .setOnlyAlertOnce(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            builder.setPriority(Notification.PRIORITY_HIGH);
            builder.setStyle(new Notification.BigTextStyle()
                .bigText("Your VPN is connected but there's no internet access. " +
                        "Please check your WiFi or cellular connection."));
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS);
            builder.setVisibility(Notification.VISIBILITY_PUBLIC);
            builder.setColor(Color.RED);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder.setChannelId(NOTIFICATION_CHANNEL_ID);
        }

        builder.setDefaults(Notification.DEFAULT_ALL);

        notificationManager.notify(NO_INTERNET_NOTIFICATION_ID, builder.build());
        Log.d(TAG, "✅ No internet notification shown");
    }

    /**
     * Show internet restored notification
     */
    private void showInternetRestoredNotification() {
        Log.d(TAG, "🔔 Showing internet restored notification");

        Intent launchIntent = context.getPackageManager()
            .getLaunchIntentForPackage(context.getPackageName());

        if (launchIntent != null) {
            launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            launchIntent.putExtra("from_internet_restored_notification", true);
            launchIntent.putExtra("notification_type", "internet_restored");
        }

        PendingIntent pendingIntent = PendingIntent.getActivity(
            context,
            INTERNET_RESTORED_NOTIFICATION_ID,
            launchIntent != null ? launchIntent : new Intent(),
            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Notification.Builder builder = new Notification.Builder(context)
            .setContentTitle("Internet Restored")
            .setContentText("Your internet connection has been restored.")
            .setSmallIcon(R.drawable.high)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setOngoing(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            builder.setPriority(Notification.PRIORITY_DEFAULT);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS);
            builder.setVisibility(Notification.VISIBILITY_PUBLIC);
            builder.setColor(Color.GREEN);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder.setChannelId(NOTIFICATION_CHANNEL_ID);
        }

        notificationManager.notify(INTERNET_RESTORED_NOTIFICATION_ID, builder.build());
        Log.d(TAG, "✅ Internet restored notification shown");
    }

    /**
     * Create notification channel for Android O+
     */
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "VPN Internet Monitor",
                NotificationManager.IMPORTANCE_HIGH
            );
            channel.setDescription("Notifications about VPN internet connectivity");
            channel.setLightColor(Color.BLUE);
            channel.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
            channel.enableVibration(true);
            channel.setVibrationPattern(new long[]{0, 500, 250, 500});

            notificationManager.createNotificationChannel(channel);
        }
    }
}