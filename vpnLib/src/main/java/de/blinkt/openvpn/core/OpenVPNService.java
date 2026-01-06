/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.openvpn.core;

import static de.blinkt.openvpn.core.ConnectionStatus.LEVEL_CONNECTED;
import static de.blinkt.openvpn.core.ConnectionStatus.LEVEL_WAITING_FOR_USER_INPUT;
import static de.blinkt.openvpn.core.NetworkSpace.IpAddress;
import de.blinkt.openvpn.R;
import android.Manifest.permission;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.UiModeManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ShortcutManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Handler.Callback;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.Process;
import android.os.RemoteException;
import android.system.OsConstants;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;
import java.util.Vector;

import de.blinkt.openvpn.DisconnectVPNActivity;
import de.blinkt.openvpn.LaunchVPN;
import de.blinkt.openvpn.VpnProfile;
import de.blinkt.openvpn.api.ExternalAppDatabase;
import de.blinkt.openvpn.core.VpnStatus.ByteCountListener;
import de.blinkt.openvpn.core.VpnStatus.StateListener;
import de.blinkt.openvpn.utils.TotalTraffic;

public class OpenVPNService extends VpnService implements StateListener, Callback, ByteCountListener, IOpenVPNServiceInternal {

    private String byteIn, byteOut;
    private String duration;
    private static final String PREFS_NAME = "VPNTimerPrefs";
    private static final String KEY_ALLOWED_DURATION = "allowed_duration_seconds";
    private static final String KEY_CONNECTION_START_TIME = "connection_start_time";
    private static final String KEY_IS_PRO_USER = "is_pro_user";
    private static final int TIMER_CHECK_INTERVAL = 10000; // Check every 10 seconds
    private Handler timerHandler;
    private Runnable timerCheckRunnable;
    private boolean isTimerMonitoringActive = false;

    // Timer related fields
    public static final String START_SERVICE = "de.blinkt.openvpn.START_SERVICE";
    public static final String START_SERVICE_STICKY = "de.blinkt.openvpn.START_SERVICE_STICKY";
    public static final String ALWAYS_SHOW_NOTIFICATION = "de.blinkt.openvpn.NOTIFICATION_ALWAYS_VISIBLE";
    public static final String DISCONNECT_VPN = "de.blinkt.openvpn.DISCONNECT_VPN";
    public static final String NOTIFICATION_CHANNEL_BG_ID = "openvpn_bg";
    public static final String NOTIFICATION_CHANNEL_NEWSTATUS_ID = "openvpn_newstat";
    public static final String NOTIFICATION_CHANNEL_USERREQ_ID = "openvpn_userreq";
    private static final String TAG = "OpenVPNService";
    public static final String VPNSERVICE_TUN = "vpnservice-tun";
    public final static String ORBOT_PACKAGE_NAME = "org.torproject.android";
    private static final String PAUSE_VPN = "de.blinkt.openvpn.PAUSE_VPN";
    private static final String RESUME_VPN = "de.blinkt.openvpn.RESUME_VPN";

    public static final String EXTRA_CHALLENGE_TXT = "de.blinkt.openvpn.core.CR_TEXT_CHALLENGE";
    public static final String EXTRA_CHALLENGE_OPENURL = "de.blinkt.openvpn.core.OPENURL_CHALLENGE";

    private static final int PRIORITY_MIN = -2;
    private static final int PRIORITY_DEFAULT = 0;
    private static final int PRIORITY_MAX = 2;
    private static boolean mNotificationAlwaysVisible = false;
    private static Class<? extends Activity> mNotificationActivityClass;
    private final Vector<String> mDnslist = new Vector<>();
    private final NetworkSpace mRoutes = new NetworkSpace();
    private final NetworkSpace mRoutesv6 = new NetworkSpace();
    private final Object mProcessLock = new Object();
    private String lastChannel;
    private Thread mProcessThread = null;
    private VpnProfile mProfile;
    private String mDomain = null;
    private CIDRIP mLocalIP = null;
    private int mMtu;
    private String mLocalIPv6 = null;
    private DeviceStateReceiver mDeviceStateReceiver;
    private boolean mDisplayBytecount = false;
    private boolean mStarting = false;
    private boolean isVpnConnected = false; // ✅ NEW: Track VPN connection state
    private long mConnecttime;
    private OpenVPNManagement mManagement;
    /*private final IBinder mBinder = new IOpenVPNServiceInternal.Stub() {

        @Override
        public boolean protect(int fd) throws RemoteException {
            return OpenVPNService.this.protect(fd);
        }

        @Override
        public void userPause(boolean shouldbePaused) throws RemoteException {
            OpenVPNService.this.userPause(shouldbePaused);
        }

        @Override
        public boolean stopVPN(boolean replaceConnection) throws RemoteException {
            return OpenVPNService.this.stopVPN(replaceConnection);
        }

        @Override
        public void addAllowedExternalApp(String packagename) throws RemoteException {
            OpenVPNService.this.addAllowedExternalApp(packagename);
        }

        @Override
        public boolean isAllowedExternalApp(String packagename) throws RemoteException {
            return OpenVPNService.this.isAllowedExternalApp(packagename);

        }

        @Override
        public void challengeResponse(String repsonse) throws RemoteException {
            OpenVPNService.this.challengeResponse(repsonse);
        }


    };*/

    private final IBinder mBinder = new LocalBinder();
    private static String state = "";
    boolean flag = false;
    private String mLastTunCfg;
    private String mRemoteGW;
    private Handler guiHandler;
    private Toast mlastToast;
    private Runnable mOpenVPNThread;
    private static final String KEY_TIMER_ALARM_SET = "timer_alarm_set";
    private PowerManager.WakeLock wakeLock;
    private AlarmManager alarmManager;
    private PendingIntent timerAlarmIntent;

    // From: http://stackoverflow.com/questions/3758606/how-to-convert-byte-size-into-human-readable-format-in-java
    public static String humanReadableByteCount(long bytes, boolean speed, Resources res) {
        if (speed)
            bytes = bytes * 8;
        int unit = speed ? 1000 : 1024;


        int exp = Math.max(0, Math.min((int) (Math.log(bytes) / Math.log(unit)), 3));

        float bytesUnit = (float) (bytes / Math.pow(unit, exp));

        if (speed)
            switch (exp) {
                case 0:
                    return res.getString(R.string.bits_per_second, bytesUnit);
                case 1:
                    return res.getString(R.string.kbits_per_second, bytesUnit);
                case 2:
                    return res.getString(R.string.mbits_per_second, bytesUnit);
                default:
                    return res.getString(R.string.gbits_per_second, bytesUnit);
            }
        else
            switch (exp) {
                case 0:
                    return res.getString(R.string.volume_byte, bytesUnit);
                case 1:
                    return res.getString(R.string.volume_kbyte, bytesUnit);
                case 2:
                    return res.getString(R.string.volume_mbyte, bytesUnit);
                default:
                    return res.getString(R.string.volume_gbyte, bytesUnit);

            }
    }

    /**
     * Sets the activity which should be opened when tapped on the permanent notification tile.
     *
     * @param activityClass The activity class to open
     */
    public static void setNotificationActivityClass(Class<? extends Activity> activityClass) {
        mNotificationActivityClass = activityClass;
    }

    PendingIntent getContentIntent() {
        try {
            if (mNotificationActivityClass != null) {
                // Let the configure Button show the Log
                Intent intent = new Intent(getBaseContext(), mNotificationActivityClass);
                String typeStart = Objects.requireNonNull(
                        mNotificationActivityClass.getField("TYPE_START").get(null)).toString();
                Integer typeFromNotify = Integer.parseInt(Objects.requireNonNull(mNotificationActivityClass.getField("TYPE_FROM_NOTIFY").get(null)).toString());
                intent.putExtra(typeStart, typeFromNotify);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK |
                        Intent.FLAG_ACTIVITY_SINGLE_TOP);
                return PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
            }
        } catch (Exception e) {
            Log.e(this.getClass().getCanonicalName(), "Build detail intent error", e);
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void addAllowedExternalApp(String packagename) throws RemoteException {
        ExternalAppDatabase extapps = new ExternalAppDatabase(OpenVPNService.this);
        extapps.addApp(packagename);
    }

    @Override
    public boolean isAllowedExternalApp(String packagename) throws RemoteException {
        ExternalAppDatabase extapps = new ExternalAppDatabase(OpenVPNService.this);
        return extapps.checkRemoteActionPermission(this, packagename);
    }

    @Override
    public void challengeResponse(String response) throws RemoteException {
        if (mManagement != null) {
            String b64response = Base64.encodeToString(response.getBytes(Charset.forName("UTF-8")), Base64.DEFAULT);
            mManagement.sendCRResponse(b64response);
        }
    }

    private void checkAndResumeTimerMonitoring() {
        try {
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

            int allowedDuration = prefs.getInt(KEY_ALLOWED_DURATION, -1);
            boolean isProUser = prefs.getBoolean(KEY_IS_PRO_USER, false);
            long startTime = prefs.getLong(KEY_CONNECTION_START_TIME, 0);

            Log.d(TAG, "checkAndResumeTimerMonitoring - Duration: " + allowedDuration +
                    ", Pro: " + isProUser + ", StartTime: " + startTime);

            if (!isProUser && allowedDuration > 0 && startTime > 0) {
                String currentStatus = OpenVPNService.getStatus();
                if (currentStatus != null && currentStatus.equals("connected")) {
                    Log.d(TAG, "Resuming timer monitoring after service restart");

                    // Check if time has already expired
                    long currentTime = System.currentTimeMillis();
                    long elapsedSeconds = (currentTime - startTime) / 1000;

                    if (elapsedSeconds >= allowedDuration) {
                        Log.d(TAG, "Time already expired, disconnecting immediately");
                        disconnectDueToTimeLimit();
                    } else {
                        startTimerMonitoring();
                    }
                } else {
                    Log.d(TAG, "Timer settings exist but VPN not connected");
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking timer monitoring: " + e.getMessage(), e);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        String action = intent.getAction();
        if (action != null && action.equals(START_SERVICE))
            return mBinder;
        else
            return super.onBind(intent);
    }

    @Override
    public void onRevoke() {
        Log.d(TAG, "🛑 ========== onRevoke CALLED ==========");

        VpnStatus.logError(R.string.permission_revoked);

        // Stop timer
        stopTimerMonitoring();

        // Stop management
        if (mManagement != null) {
            try {
                mManagement.stopVPN(false);
            } catch (Exception e) {
                Log.e(TAG, "Error in onRevoke: " + e.getMessage());
            }
            mManagement = null;
        }

        // Force stop process
        forceStopOpenVpnProcess();

        // Reset flags
        isVpnConnected = false;
        mStarting = false;

        endVpnService();
    }


    // Similar to revoke but do not try to stop process

    public void openvpnStopped() {
        Log.d(TAG, "🛑 ========== openvpnStopped CALLED ==========");

        // ✅ Reset mStarting flag IMMEDIATELY
        synchronized (mProcessLock) {
            mStarting = false;
            mProcessThread = null;
        }

        // ✅ Reset state to idle (not disconnected)
        state = "idle";

        // Stop timer first
        stopTimerMonitoring();

        // Clean up management
        if (mManagement != null) {
            try {
                mManagement.stopVPN(false);
            } catch (Exception e) {
                Log.e(TAG, "Error stopping management: " + e.getMessage());
            }
            mManagement = null;
        }

        // Force stop process
        forceStopOpenVpnProcess();

        // Reset connection state
        isVpnConnected = false;
        mDisplayBytecount = false;
        mOpenVPNThread = null;

        Log.d(TAG, "✅ openvpnStopped completed:");
        Log.d(TAG, "   - mStarting: " + mStarting);
        Log.d(TAG, "   - state: " + state);
        Log.d(TAG, "   - Calling endVpnService...");

        endVpnService();
    }


    // ============= FIX 2: In endVpnService() method =============
    public void endVpnService() {
        Log.d(TAG, "🛑 ========== endVpnService CALLED ==========");

        // Stop timer
        stopTimerMonitoring();

        // ✅ CRITICAL: Reset state and flags FIRST
        state = "idle"; // Use "idle" not "disconnected" to allow reconnection
        isVpnConnected = false;

        // ✅ CRITICAL: Reset mStarting flag to allow reconnection
        synchronized (mProcessLock) {
            mStarting = false;
            mProcessThread = null;
        }

        mDisplayBytecount = false;
        mOpenVPNThread = null;

        Log.d(TAG, "✅ Flags reset:");
        Log.d(TAG, "   - state: " + state);
        Log.d(TAG, "   - mStarting: " + mStarting);
        Log.d(TAG, "   - isVpnConnected: " + isVpnConnected);

        // Clean up management interface
        if (mManagement != null) {
            try {
                mManagement.stopVPN(false);
            } catch (Exception e) {
                Log.e(TAG, "Error in endVpnService management cleanup: " + e.getMessage());
            }
            mManagement = null;
        }

        // Remove listeners
        VpnStatus.removeByteCountListener(this);

        // Unregister receiver
        unregisterDeviceStateReceiver();

        // Clear profile connection
        ProfileManager.setConntectedVpnProfileDisconnected(this);

        if (!mStarting) {
            stopForeground(true);

            if (!mNotificationAlwaysVisible) {
                // ✅ DON'T call stopSelf() here - service should stay alive for reconnection
                VpnStatus.removeStateListener(this);
            }
        }

        // ✅ Update state to IDLE (allows reconnection)
        VpnStatus.updateStateString("NOPROCESS", "", R.string.state_noprocess,
                ConnectionStatus.LEVEL_NOTCONNECTED);

        Log.d(TAG, "✅ endVpnService completed");
    }


    @RequiresApi(Build.VERSION_CODES.O)
    private String createNotificationChannel(String channelId, String channelName) {
        NotificationChannel chan = new NotificationChannel(channelId,
                channelName, NotificationManager.IMPORTANCE_NONE);
        chan.setLightColor(Color.BLUE);
        chan.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
        NotificationManager service = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        service.createNotificationChannel(chan);
        return channelId;
    }

    private void showNotification(final String msg, String tickerText, @NonNull String channel,
                                  long when, ConnectionStatus status, Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (channel.equals(NOTIFICATION_CHANNEL_BG_ID)) {
                channel = createNotificationChannel(channel, getAppName(this) + " VPN Background");
            } else if (channel.equals(NOTIFICATION_CHANNEL_NEWSTATUS_ID)) {
                channel = createNotificationChannel(channel, getAppName(this) + " VPN Stats");
            }
        } else {
            // If earlier version channel ID is not used
            // https://developer.android.com/reference/android/support/v4/app/NotificationCompat.Builder.html#NotificationCompat.Builder(android.content.Context)
            channel = "";
        }

        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        android.app.Notification.Builder nbuilder = new Notification.Builder(this);

        int priority;
        if (channel.equals(NOTIFICATION_CHANNEL_BG_ID))
            priority = PRIORITY_MIN;
        else if (channel.equals(NOTIFICATION_CHANNEL_USERREQ_ID))
            priority = PRIORITY_MAX;
        else
            priority = PRIORITY_DEFAULT;

        if (mProfile != null)
            nbuilder.setContentTitle(getString(R.string.notifcation_title, mProfile.mName));
        else
            nbuilder.setContentTitle(getString(R.string.notifcation_title_notconnect));

        Intent launchIntent = getPackageManager().getLaunchIntentForPackage(getApplicationContext().getPackageName());
        PendingIntent pendingIntent = PendingIntent.getActivity(getApplicationContext(), 0, launchIntent, PendingIntent.FLAG_IMMUTABLE);

        nbuilder.setContentText(msg);
        nbuilder.setOnlyAlertOnce(true);
        nbuilder.setOngoing(true);
        nbuilder.setSmallIcon(R.drawable.ic_notification);
        nbuilder.setContentIntent(pendingIntent);

        if (when != 0) nbuilder.setWhen(when);

        jbNotificationExtras(priority, nbuilder);
        addVpnActionsToNotification(nbuilder);


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            lpNotificationExtras(nbuilder, Notification.CATEGORY_SERVICE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            //noinspection NewApi
            nbuilder.setChannelId(channel);
            if (mProfile != null)
                //noinspection NewApi
                nbuilder.setShortcutId(mProfile.getUUIDString());

        }

        if (tickerText != null && !tickerText.equals(""))
            nbuilder.setTicker(tickerText);
        try {
            Notification notification = nbuilder.build();

            int notificationId = channel.hashCode();

            mNotificationManager.notify(notificationId, notification);

            startForeground(notificationId, notification);

            if (lastChannel != null && !channel.equals(lastChannel)) {
                // Cancel old notification
                mNotificationManager.cancel(lastChannel.hashCode());
            }
        } catch (Throwable th) {
            Log.e(getClass().getCanonicalName(), "Error when show notification", th);
        }

        // Check if running on a TV
//        if (runningOnAndroidTV() && !(priority < 0))
//            guiHandler.post(() -> {
//                if (mlastToast != null)
//                    mlastToast.cancel();
//                String toastText = String.format(Locale.getDefault(), "%s - %s", mProfile.mName, msg);
//                mlastToast = Toast.makeText(getBaseContext(), toastText, Toast.LENGTH_SHORT);
//                mlastToast.show();
//            });
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private void lpNotificationExtras(Notification.Builder nbuilder, String category) {
        nbuilder.setCategory(category);
        nbuilder.setLocalOnly(true);

    }

    private String getAppName(Context context) {
        PackageManager packageManager = context.getPackageManager();
        ApplicationInfo applicationInfo;
        String applicationName;

        try {
            applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 0);
            applicationName = (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            applicationName = "Unknown";
        }

        return applicationName;
    }

    private boolean runningOnAndroidTV() {
        UiModeManager uiModeManager = (UiModeManager) getSystemService(UI_MODE_SERVICE);
        return uiModeManager.getCurrentModeType() == Configuration.UI_MODE_TYPE_TELEVISION;
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN)
    private void jbNotificationExtras(int priority,
                                      android.app.Notification.Builder nbuilder) {
        try {
            if (priority != 0) {
                Method setpriority = nbuilder.getClass().getMethod("setPriority", int.class);
                setpriority.invoke(nbuilder, priority);

                Method setUsesChronometer = nbuilder.getClass().getMethod("setUsesChronometer", boolean.class);
                setUsesChronometer.invoke(nbuilder, true);

            }

            //ignore exception
        } catch (NoSuchMethodException | IllegalArgumentException |
                 InvocationTargetException | IllegalAccessException e) {
            VpnStatus.logException(e);
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    private void addVpnActionsToNotification(Notification.Builder nbuilder) {
        Intent disconnectVPN = new Intent(this, DisconnectVPNActivity.class);
        disconnectVPN.setAction(DISCONNECT_VPN);
        PendingIntent disconnectPendingIntent = PendingIntent.getActivity(this, 0, disconnectVPN, PendingIntent.FLAG_IMMUTABLE);

        nbuilder.addAction(R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.cancel_connection), disconnectPendingIntent);

        // Intent pauseVPN = new Intent(this, OpenVPNService.class);
        // if (mDeviceStateReceiver == null || !mDeviceStateReceiver.isUserPaused()) {
        //     pauseVPN.setAction(PAUSE_VPN);
        //     PendingIntent pauseVPNPending = PendingIntent.getService(this, 0, pauseVPN, 0);
        //     nbuilder.addAction(R.drawable.ic_menu_pause,
        //             getString(R.string.pauseVPN), pauseVPNPending);

        // } else {
        //     pauseVPN.setAction(RESUME_VPN);
        //     PendingIntent resumeVPNPending = PendingIntent.getService(this, 0, pauseVPN, 0);
        //     nbuilder.addAction(R.drawable.ic_menu_play,
        //             getString(R.string.resumevpn), resumeVPNPending);
        // }
    }

    PendingIntent getUserInputIntent(String needed) {
        Intent intent = new Intent(getApplicationContext(), LaunchVPN.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        intent.putExtra("need", needed);
        Bundle b = new Bundle();
        b.putString("need", needed);
        PendingIntent pIntent = PendingIntent.getActivity(this, 12, intent, PendingIntent.FLAG_IMMUTABLE);
        return pIntent;
    }

    PendingIntent getGraphPendingIntent() {
        // Let the configure Button show the Log


        Intent intent = new Intent();
        intent.setComponent(new ComponentName(this, getPackageName() + ".view.MainActivity"));

        intent.putExtra("PAGE", "graph");
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        PendingIntent startLW = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
        intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        return startLW;

    }

    synchronized void registerDeviceStateReceiver(OpenVPNManagement magnagement) {
        // Registers BroadcastReceiver to track network connection changes.
        IntentFilter filter = new IntentFilter();
        filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_SCREEN_ON);
        mDeviceStateReceiver = new DeviceStateReceiver(magnagement);

        // Fetch initial network state
        mDeviceStateReceiver.networkStateChange(this);

        registerReceiver(mDeviceStateReceiver, filter);
        VpnStatus.addByteCountListener(mDeviceStateReceiver);

        /*if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            addLollipopCMListener(); */
    }

    synchronized void unregisterDeviceStateReceiver() {
        if (mDeviceStateReceiver != null)
            try {
                VpnStatus.removeByteCountListener(mDeviceStateReceiver);
                this.unregisterReceiver(mDeviceStateReceiver);
            } catch (IllegalArgumentException ignored) {
                // I don't know why  this happens:
                // java.lang.IllegalArgumentException: Receiver not registered: de.blinkt.openvpn.NetworkSateReceiver@41a61a10
                // Ignore for now ...
            }
        mDeviceStateReceiver = null;

        /*if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            removeLollipopCMListener();*/

    }

    public void userPause(boolean shouldBePaused) {
        if (mDeviceStateReceiver != null)
            mDeviceStateReceiver.userPause(shouldBePaused);
    }

    @Override
    public boolean stopVPN(boolean replaceConnection) throws RemoteException {
        if (getManagement() != null)
            return getManagement().stopVPN(replaceConnection);
        else
            return false;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // ✅ CRITICAL: Handle force disconnect and cleanup FIRST
        if (intent != null && "FORCE_DISCONNECT_AND_CLEANUP".equals(intent.getAction())) {
            Log.d(TAG, "🛑 ========== FORCE_DISCONNECT_AND_CLEANUP ==========");

            try {
                // ✅ CRITICAL: Reset mStarting flag FIRST
                synchronized (mProcessLock) {
                    mStarting = false;
                }
                Log.d(TAG, "✅ mStarting reset to false");

                // Stop timer monitoring
                stopTimerMonitoring();

                // Stop management interface
                if (mManagement != null) {
                    try {
                        mManagement.stopVPN(false);
                    } catch (Exception e) {
                        Log.e(TAG, "Error stopping management: " + e.getMessage());
                    }
                    mManagement = null;
                }

                // Force stop OpenVPN process
                forceStopOpenVpnProcess();

                // ✅ CRITICAL: Reset ALL flags and state
                isVpnConnected = false;
                mStarting = false; // Double-check it's false
                mDisplayBytecount = false;
                state = "idle"; // Reset static state

                synchronized (mProcessLock) {
                    mProcessThread = null;
                }

                // Clear OpenVPN thread
                mOpenVPNThread = null;

                // ✅ CRITICAL: Update VPN status to IDLE (not disconnected)
                VpnStatus.updateStateString("NOPROCESS", "",
                        R.string.state_noprocess, ConnectionStatus.LEVEL_NOTCONNECTED);

                // Unregister device state receiver
                unregisterDeviceStateReceiver();

                // Clear profile connection
                ProfileManager.setConntectedVpnProfileDisconnected(this);

                // Stop foreground and clear notification
                stopForeground(true);

                // Clear timer preferences
                SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                prefs.edit().clear().commit();

                Log.d(TAG, "✅ FORCE_DISCONNECT_AND_CLEANUP completed");
                Log.d(TAG, "   - mStarting: " + mStarting);
                Log.d(TAG, "   - isVpnConnected: " + isVpnConnected);
                Log.d(TAG, "   - state: " + state);

                // ✅ DON'T call stopSelf() here - let the service stay alive for reconnection

            } catch (Exception e) {
                Log.e(TAG, "❌ Error in FORCE_DISCONNECT_AND_CLEANUP: " + e.getMessage(), e);
            }

            return START_NOT_STICKY;
        }

        // ✅ CRITICAL FIX: Call startForeground() IMMEDIATELY before any other logic
        // This ensures Android doesn't kill the service for timeout
        VpnStatus.logInfo(R.string.building_configration);
        VpnStatus.updateStateString("VPN_GENERATE_CONFIG", "", R.string.building_configration, ConnectionStatus.LEVEL_START);

        // ✅ MUST call this FIRST to avoid foreground service timeout
        showNotification(VpnStatus.getLastCleanLogMessage(this),
                VpnStatus.getLastCleanLogMessage(this),
                NOTIFICATION_CHANNEL_NEWSTATUS_ID,
                0,
                ConnectionStatus.LEVEL_START,
                null);

        // Handle force disconnect
        if (intent != null && "FORCE_DISCONNECT".equals(intent.getAction())) {
            disconnectDueToTimeLimit();
            return START_NOT_STICKY;
        }

        // ✅ HANDLE TIMER UPDATE (when user purchases more time)
        if (intent != null && "UPDATE_TIMER".equals(intent.getAction())) {
            Log.d(TAG, "🔄 ========== RECEIVED UPDATE_TIMER INTENT ==========");
            Log.d(TAG, "🔄 Thread: " + Thread.currentThread().getName());
            Log.d(TAG, "🔄 Timestamp: " + System.currentTimeMillis());

            int newDurationSeconds = intent.getIntExtra("duration_seconds", -1);
            boolean isProUser = intent.getBooleanExtra("is_pro_user", false);

            Log.d(TAG, "📥 Intent extras:");
            Log.d(TAG, "   - duration_seconds: " + newDurationSeconds);
            Log.d(TAG, "   - is_pro_user: " + isProUser);
            Log.d(TAG, "   - VPN connected status: " + isVpnConnected);

            // ✅ Check if VPN is actually connected before updating timer
            String currentStatus = OpenVPNService.getStatus();
            boolean vpnActuallyConnected = isVpnConnected &&
                    (currentStatus != null && currentStatus.equals("connected"));

            if (!vpnActuallyConnected) {
                Log.e(TAG, "❌ VPN not connected, aborting timer update");
                Log.d(TAG, "   isVpnConnected flag: " + isVpnConnected);
                Log.d(TAG, "   status string: " + currentStatus);
                Log.d(TAG, "========== UPDATE_TIMER ABORTED ==========");
                return START_STICKY;
            }

            Log.d(TAG, "✅ VPN is connected, proceeding with timer update");

            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

            // Log BEFORE values
            Log.d(TAG, "📊 BEFORE update - SharedPreferences:");
            Log.d(TAG, "   - allowed_duration_seconds: " + prefs.getInt(KEY_ALLOWED_DURATION, -999));
            Log.d(TAG, "   - connection_start_time: " + prefs.getLong(KEY_CONNECTION_START_TIME, -999));
            Log.d(TAG, "   - is_pro_user: " + prefs.getBoolean(KEY_IS_PRO_USER, false));
            Log.d(TAG, "   - timer_monitoring_active: " + isTimerMonitoringActive);

            SharedPreferences.Editor editor = prefs.edit();

            if (isProUser) {
                Log.d(TAG, "🌟 PRO user update - setting unlimited time");
                editor.putInt(KEY_ALLOWED_DURATION, -1);
                editor.putBoolean(KEY_IS_PRO_USER, true);
                editor.commit();

                Log.d(TAG, "🛑 Stopping timer monitoring for PRO user");
                stopTimerMonitoring();
                cancelTimerAlarm();

                Log.d(TAG, "========== UPDATE_TIMER COMPLETED (PRO USER) ==========");
            } else {
                // ✅ CRITICAL: Reset start time to NOW when adding time
                long currentTime = System.currentTimeMillis();
                long oldStartTime = prefs.getLong(KEY_CONNECTION_START_TIME, 0);
                long elapsedSeconds = oldStartTime > 0 ? (currentTime - oldStartTime) / 1000 : 0;

                Log.d(TAG, "⏱️ Regular user update:");
                Log.d(TAG, "   - Old start time: " + oldStartTime);
                Log.d(TAG, "   - Current time: " + currentTime);
                Log.d(TAG, "   - Elapsed seconds: " + elapsedSeconds);
                Log.d(TAG, "   - NEW total duration: " + newDurationSeconds);
                Log.d(TAG, "   - RESETTING start time to NOW");

                editor.putInt(KEY_ALLOWED_DURATION, newDurationSeconds);
                editor.putLong(KEY_CONNECTION_START_TIME, currentTime); // ✅ RESET to NOW
                editor.putBoolean(KEY_IS_PRO_USER, false);
                boolean commitSuccess = editor.commit();

                Log.d(TAG, "💾 Preferences commit result: " + commitSuccess);

                // Log AFTER values
                Log.d(TAG, "📊 AFTER update - SharedPreferences:");
                Log.d(TAG, "   - allowed_duration_seconds: " + prefs.getInt(KEY_ALLOWED_DURATION, -999));
                Log.d(TAG, "   - connection_start_time: " + prefs.getLong(KEY_CONNECTION_START_TIME, -999));
                Log.d(TAG, "   - is_pro_user: " + prefs.getBoolean(KEY_IS_PRO_USER, false));

                // ✅ CRITICAL: Restart timer monitoring with new duration
                if (vpnActuallyConnected) {
                    Log.d(TAG, "🔄 Restarting timer monitoring...");

                    // Stop existing timer and alarm
                    Log.d(TAG, "🛑 Stopping existing timer and alarm");
                    stopTimerMonitoring();
                    cancelTimerAlarm();

                    // Wait a moment for cleanup
                    new Handler(Looper.getMainLooper()).postDelayed(() -> {
                        Log.d(TAG, "🚀 Starting fresh timer with NEW duration");
                        startTimerMonitoring();
                        Log.d(TAG, "✅ Timer monitoring restarted successfully");
                    }, 500); // 500ms delay for cleanup
                } else {
                    Log.e(TAG, "❌ VPN disconnected during update process");
                }

                Log.d(TAG, "========== UPDATE_TIMER COMPLETED ==========");
            }

            return START_STICKY;
        }

        // ✅ HANDLE TIMER MONITORING INTENT
        if (intent != null && "START_TIMER_MONITORING".equals(intent.getAction())) {
            Log.d(TAG, "Received START_TIMER_MONITORING intent");

            // Get duration and pro status from intent
            int durationSeconds = intent.getIntExtra("duration_seconds", -1);
            boolean isProUser = intent.getBooleanExtra("is_pro_user", false);

            Log.d(TAG, "Timer params - Duration: " + durationSeconds + ", Pro: " + isProUser);

            if (durationSeconds > 0 || isProUser) {
                // Save to preferences
                SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                SharedPreferences.Editor editor = prefs.edit();

                if (isProUser) {
                    editor.putInt(KEY_ALLOWED_DURATION, -1);
                    editor.putBoolean(KEY_IS_PRO_USER, true);
                    Log.d(TAG, "Saved pro user status - unlimited VPN time");
                } else {
                    editor.putInt(KEY_ALLOWED_DURATION, durationSeconds);
                    editor.putLong(KEY_CONNECTION_START_TIME, System.currentTimeMillis());
                    editor.putBoolean(KEY_IS_PRO_USER, false);
                    Log.d(TAG, "Saved timer settings - Duration: " + durationSeconds +
                            " seconds, Start time: " + System.currentTimeMillis());
                }
                editor.apply();

                // Start monitoring if VPN is already connected
                String currentStatus = OpenVPNService.getStatus();
                Log.d(TAG, "Current VPN status: " + currentStatus);

                if (currentStatus != null && currentStatus.equals("connected")) {
                    startTimerMonitoring();
                } else {
                    Log.d(TAG, "VPN not connected yet, timer will start when connected");
                }
            }

            return START_STICKY;
        }

        // ✅ EXISTING CODE - Handle always show notification
        if (intent != null && intent.getBooleanExtra(ALWAYS_SHOW_NOTIFICATION, false))
            mNotificationAlwaysVisible = true;

        VpnStatus.addStateListener(this);
        VpnStatus.addByteCountListener(this);

        guiHandler = new Handler(getMainLooper());

        // ✅ EXISTING CODE - Handle disconnect
        if (intent != null && DISCONNECT_VPN.equals(intent.getAction())) {
            try {
                stopVPN(false);
            } catch (RemoteException e) {
                VpnStatus.logException(e);
            }
            return START_NOT_STICKY;
        }

        // ✅ EXISTING CODE - Handle pause
        if (intent != null && PAUSE_VPN.equals(intent.getAction())) {
            if (mDeviceStateReceiver != null)
                mDeviceStateReceiver.userPause(true);
            return START_NOT_STICKY;
        }

        // ✅ EXISTING CODE - Handle resume
        if (intent != null && RESUME_VPN.equals(intent.getAction())) {
            if (mDeviceStateReceiver != null)
                mDeviceStateReceiver.userPause(false);
            return START_NOT_STICKY;
        }

        // ✅ EXISTING CODE - Handle start service
        if (intent != null && START_SERVICE.equals(intent.getAction()))
            return START_NOT_STICKY;

        if (intent != null && START_SERVICE_STICKY.equals(intent.getAction())) {
            return START_REDELIVER_INTENT;
        }

        // ✅ EXISTING CODE - Get profile from intent
        if (intent != null && intent.hasExtra(getPackageName() + ".profileUUID")) {
            String profileUUID = intent.getStringExtra(getPackageName() + ".profileUUID");
            int profileVersion = intent.getIntExtra(getPackageName() + ".profileVersion", 0);
            // Try for 10s to get current version of the profile
            mProfile = ProfileManager.get(this, profileUUID, profileVersion, 100);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N_MR1) {
                updateShortCutUsage(mProfile);
            }

        } else {
            /* The intent is null when we are set as always-on or the service has been restarted. */
            mProfile = ProfileManager.getLastConnectedProfile(this);
            VpnStatus.logInfo(R.string.service_restarted);

            /* Got no profile, just stop */
            if (mProfile == null) {
                Log.d("OpenVPN", "Got no last connected profile on null intent. Assuming always on.");
                mProfile = ProfileManager.getAlwaysOnVPN(this);

                if (mProfile == null) {
                    stopSelf(startId);
                    return START_NOT_STICKY;
                }
            }
            /* Do the asynchronous keychain certificate stuff */
            mProfile.checkForRestart(this);
        }

        if (mProfile == null) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        /* start the OpenVPN process itself in a background thread */
        new Thread(this::startOpenVPN).start();

        ProfileManager.setConnectedVpnProfile(this, mProfile);
        VpnStatus.setConnectedVPNProfile(mProfile.getUUIDString());

        // ✅ ANSWER TO YOUR QUESTION: YES, KEEP THIS CODE!
        // This ensures timer monitoring resumes after service restart
        // Only schedule timer check if we're actually connecting
        if (mProfile != null && timerHandler != null) {
            // Clear any existing delayed callbacks first
            timerHandler.removeCallbacksAndMessages(null);

            timerHandler.postDelayed(() -> {
                String currentStatus = OpenVPNService.getStatus();
                if ("connected".equals(currentStatus)) {
                    SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                    int allowedDuration = prefs.getInt(KEY_ALLOWED_DURATION, -1);
                    boolean isProUser = prefs.getBoolean(KEY_IS_PRO_USER, false);

                    if (!isProUser && allowedDuration > 0 && !isTimerMonitoringActive) {
                        Log.d(TAG, "Starting timer monitoring after connection");
                        startTimerMonitoring();
                    }
                }
            }, 3000);
        }

        return START_STICKY;
    }

    private void resetConnectionState() {
        Log.d(TAG, "🔄 ========== resetConnectionState CALLED ==========");

        isVpnConnected = false;
        mStarting = false;
        mDisplayBytecount = false;

        // Stop timer
        stopTimerMonitoring();
        if (timerHandler != null) {
            timerHandler.removeCallbacksAndMessages(null);
        }

        // Clean management
        if (mManagement != null) {
            try {
                mManagement.stopVPN(false);
            } catch (Exception e) {
                Log.e(TAG, "Error in resetConnectionState: " + e.getMessage());
            }
            mManagement = null;
        }

        // Reset time tracking
        c = Calendar.getInstance().getTimeInMillis();
        lastPacketReceive = 0;

        Log.d(TAG, "✅ resetConnectionState COMPLETED");
    }
    @RequiresApi(Build.VERSION_CODES.N_MR1)
    private void updateShortCutUsage(VpnProfile profile) {
        if (profile == null)
            return;
        ShortcutManager shortcutManager = getSystemService(ShortcutManager.class);
        shortcutManager.reportShortcutUsed(profile.getUUIDString());
    }

    private void startOpenVPN() {
        Log.d(TAG, "🚀 ========== startOpenVPN CALLED ==========");
        Log.d(TAG, "   Thread: " + Thread.currentThread().getName());
        Log.d(TAG, "   mStarting: " + mStarting);
        Log.d(TAG, "   isVpnConnected: " + isVpnConnected);

        // ✅ CRITICAL: Don't block if reconnecting after manual disconnect
        synchronized (mProcessLock) {
            if (mStarting && mProcessThread != null) {
                // Only block if there's actually a process running
                Log.w(TAG, "⚠️ Already starting VPN with active process, ignoring duplicate");
                return;
            }
            mStarting = true;
            Log.d(TAG, "✅ Set mStarting = true");
        }

        // ✅ CRITICAL: Clean up any lingering connections
        if (isVpnConnected || mManagement != null || mProcessThread != null) {
            Log.w(TAG, "⚠️ Cleaning up previous connection before starting new one");

            if (mManagement != null) {
                try {
                    mManagement.stopVPN(false);
                } catch (Exception e) {
                    Log.e(TAG, "Error stopping old VPN: " + e.getMessage());
                }
                mManagement = null;
            }

            forceStopOpenVpnProcess();
            isVpnConnected = false;

            // Wait for cleanup
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }


        // Write config file
        try {
            mProfile.writeConfigFile(this);
            Log.d(TAG, "✅ Config file written");
        } catch (IOException e) {
            VpnStatus.logException("Error writing config file", e);
            mStarting = false;
            endVpnService();
            return;
        }

        String nativeLibraryDirectory = getApplicationInfo().nativeLibraryDir;
        String tmpDir;
        try {
            tmpDir = getApplication().getCacheDir().getCanonicalPath();
        } catch (IOException e) {
            e.printStackTrace();
            tmpDir = "/tmp";
        }

        String[] argv = VPNLaunchHelper.buildOpenvpnArgv(this);

        // ✅ CRITICAL: Stop old OpenVPN process completely
        Log.d(TAG, "🛑 Stopping old OpenVPN process...");
        stopOldOpenVPNProcess();

        // ✅ CRITICAL: Ensure management is null
        if (mManagement != null) {
            Log.w(TAG, "⚠️ Management still exists after stopOldOpenVPNProcess, forcing null");
            mManagement = null;
        }

        // Wait for cleanup
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // ✅ Reset starting flag before creating new connection
        mStarting = false;
        Log.d(TAG, "✅ Reset mStarting = false, ready to create new connection");

        boolean useOpenVPN3 = VpnProfile.doUseOpenVPN3(this);

        // Create new management interface
        if (!useOpenVPN3) {
            Log.d(TAG, "🔧 Creating new OpenVPN management thread");
            OpenVpnManagementThread ovpnManagementThread = new OpenVpnManagementThread(mProfile, this);
            if (ovpnManagementThread.openManagementInterface(this)) {
                Thread mSocketManagerThread = new Thread(ovpnManagementThread, "OpenVPNManagementThread");
                mSocketManagerThread.start();
                mManagement = ovpnManagementThread;
                VpnStatus.logInfo("started Socket Thread");
                Log.d(TAG, "✅ New management interface created successfully");
            } else {
                Log.e(TAG, "❌ Failed to open management interface");
                mStarting = false;
                endVpnService();
                return;
            }
        }

        Runnable processThread;
        if (useOpenVPN3) {
            OpenVPNManagement mOpenVPN3 = instantiateOpenVPN3Core();
            processThread = (Runnable) mOpenVPN3;
            mManagement = mOpenVPN3;
        } else {
            processThread = new OpenVPNThread(this, argv, nativeLibraryDirectory, tmpDir);
            mOpenVPNThread = processThread;
        }

        synchronized (mProcessLock) {
            mProcessThread = new Thread(processThread, "OpenVPNProcessThread");
            mProcessThread.start();
            Log.d(TAG, "✅ OpenVPN process thread started");
        }

        new Handler(getMainLooper()).post(() -> {
            if (mDeviceStateReceiver != null)
                unregisterDeviceStateReceiver();
            registerDeviceStateReceiver(mManagement);
            Log.d(TAG, "✅ Device state receiver registered");
        });

        Log.d(TAG, "========== startOpenVPN COMPLETED ==========");
    }

    private void stopOldOpenVPNProcess() {
        Log.d(TAG, "🛑 ========== stopOldOpenVPNProcess CALLED ==========");

        if (mManagement != null) {
            Log.d(TAG, "   Stopping via management interface");

            if (mOpenVPNThread != null) {
                try {
                    ((OpenVPNThread) mOpenVPNThread).setReplaceConnection();
                } catch (Exception e) {
                    Log.e(TAG, "Error setting replace connection: " + e.getMessage());
                }
            }

            try {
                if (mManagement.stopVPN(true)) {
                    Log.d(TAG, "   Management stopVPN returned true, waiting 1s...");
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Error stopping VPN via management: " + e.getMessage());
            }

            // ✅ CRITICAL: Always set to null
            mManagement = null;
            Log.d(TAG, "   ✅ Management set to null");
        }

        // Force stop the process
        forceStopOpenVpnProcess();

        Log.d(TAG, "========== stopOldOpenVPNProcess COMPLETED ==========");
    }
    //this wil work
    public void forceStopOpenVpnProcess() {
        Log.d(TAG, "🛑 ========== forceStopOpenVpnProcess CALLED ==========");

        synchronized (mProcessLock) {
            if (mProcessThread != null) {
                Log.d(TAG, "   Interrupting process thread");
                mProcessThread.interrupt();

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                mProcessThread = null;
                Log.d(TAG, "   ✅ Process thread set to null");
            } else {
                Log.d(TAG, "   No process thread to stop");
            }
        }

        mOpenVPNThread = null;
        Log.d(TAG, "========== forceStopOpenVpnProcess COMPLETED ==========");
    }



    private OpenVPNManagement instantiateOpenVPN3Core() {
        try {
            Class cl = Class.forName("de.blinkt.openvpn.core.OpenVPNThreadv3");
            return (OpenVPNManagement) cl.getConstructor(OpenVPNService.class, VpnProfile.class).newInstance(this, mProfile);
        } catch (IllegalArgumentException | InstantiationException | InvocationTargetException |
                 NoSuchMethodException | ClassNotFoundException | IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }


    @Override
    public IBinder asBinder() {
        return mBinder;
    }

    private HandlerThread timerThread;


    @Override
    public void onCreate() {
        super.onCreate();

        // Initialize wake lock to keep CPU awake for timer checks
        PowerManager powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OpenVPN::TimerWakeLock");

        timerThread = new HandlerThread("OpenVPNTimerThread", Process.THREAD_PRIORITY_BACKGROUND);
        timerThread.start();

        timerHandler = new Handler(timerThread.getLooper());
        setupTimerCheck();

        alarmManager = (AlarmManager) getSystemService(Context.ALARM_SERVICE);

        // Check and resume timer monitoring
        checkAndResumeTimerMonitoring();
    }

    private void setupTimerCheck() {
        timerCheckRunnable = new Runnable() {
            @Override
            public void run() {
                if (isTimerMonitoringActive) {
                    // Acquire wake lock before check
                    if (wakeLock != null && !wakeLock.isHeld()) {
                        wakeLock.acquire(30000); // 30 second timeout
                    }

                    try {
                        checkVpnTimeLimit();
                    } finally {
                        // Release wake lock after check
                        if (wakeLock != null && wakeLock.isHeld()) {
                            wakeLock.release();
                        }
                    }

                    // Schedule next check
                    if (isTimerMonitoringActive) {
                        timerHandler.postDelayed(this, TIMER_CHECK_INTERVAL);
                    }
                }
            }
        };
    }

    private void checkVpnTimeLimit() {
        try {
            Log.d(TAG, "⏰ ========== checkVpnTimeLimit START ==========");
            Log.d(TAG, "⏰ Timestamp: " + System.currentTimeMillis());

            // ✅ First check if VPN is still connected
            if (!isVpnConnected) {
                Log.d(TAG, "❌ VPN not connected, stopping timer monitoring");
                stopTimerMonitoring();
                return;
            }
            Log.d(TAG, "✅ VPN is connected");

            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

            boolean isProUser = prefs.getBoolean(KEY_IS_PRO_USER, false);
            int allowedDuration = prefs.getInt(KEY_ALLOWED_DURATION, -1);
            long startTime = prefs.getLong(KEY_CONNECTION_START_TIME, 0);

            Log.d(TAG, "📊 Timer values:");
            Log.d(TAG, "   - isProUser: " + isProUser);
            Log.d(TAG, "   - allowedDuration: " + allowedDuration + " seconds");
            Log.d(TAG, "   - startTime: " + startTime);

            if (isProUser) {
                Log.d(TAG, "🌟 Pro user - no time limit");
                return;
            }

            if (allowedDuration <= 0) {
                Log.d(TAG, "⚠️ No time limit set or invalid duration");
                return;
            }

            if (startTime == 0) {
                Log.d(TAG, "⚠️ No start time recorded");
                return;
            }

            long currentTime = System.currentTimeMillis();
            long elapsedSeconds = (currentTime - startTime) / 1000;
            long remainingSeconds = allowedDuration - elapsedSeconds;

            Log.d(TAG, "⏱️ TIME CALCULATION:");
            Log.d(TAG, "   - Current time: " + currentTime);
            Log.d(TAG, "   - Start time: " + startTime);
            Log.d(TAG, "   - Time difference (ms): " + (currentTime - startTime));
            Log.d(TAG, "   - Elapsed seconds: " + elapsedSeconds);
            Log.d(TAG, "   - Allowed duration: " + allowedDuration);
            Log.d(TAG, "   - REMAINING seconds: " + remainingSeconds);

            // Show warning at 1 minute
            if (remainingSeconds <= 60 && remainingSeconds > 50) {
                Log.d(TAG, "⚠️ Time warning: " + remainingSeconds + " seconds remaining");
                showTimeWarningNotification(remainingSeconds);
            }

            // Time's up - disconnect
            if (remainingSeconds <= 0) {
                Log.d(TAG, "⏰ ========== TIME LIMIT REACHED ==========");
                Log.d(TAG, "🛑 VPN time expired - disconnecting NOW");
                Log.d(TAG, "   - Elapsed: " + elapsedSeconds + "s");
                Log.d(TAG, "   - Allowed: " + allowedDuration + "s");
                Log.d(TAG, "   - Overtime by: " + Math.abs(remainingSeconds) + "s");
                disconnectDueToTimeLimit();
            }

            Log.d(TAG, "========== checkVpnTimeLimit END ==========");

        } catch (Exception e) {
            Log.e(TAG, "❌ Error in checkVpnTimeLimit: " + e.getMessage(), e);
        }
    }

    private void showTimeWarningNotification(long remainingSeconds) {
        try {
            String channel = NOTIFICATION_CHANNEL_NEWSTATUS_ID;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                channel = createNotificationChannel(channel, getAppName(this) + " VPN Warning");
            }

            NotificationManager mNotificationManager =
                    (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

            Notification.Builder nbuilder = new Notification.Builder(this);

            nbuilder.setContentTitle("VPN Time Limit Warning");
            nbuilder.setContentText(String.format("VPN will disconnect in %d seconds. Purchase more time to continue.", remainingSeconds));
            nbuilder.setSmallIcon(R.drawable.ic_notification);
            nbuilder.setAutoCancel(true);
            nbuilder.setOngoing(false);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                nbuilder.setPriority(Notification.PRIORITY_HIGH);
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                nbuilder.setCategory(Notification.CATEGORY_STATUS);
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nbuilder.setChannelId(channel);
            }

            Notification notification = nbuilder.build();
            mNotificationManager.notify(9999, notification);

        } catch (Exception e) {
            Log.e(TAG, "Error showing warning notification: " + e.getMessage(), e);
        }
    }

    private void disconnectDueToTimeLimit() {
        try {
            Log.d(TAG, "=== DISCONNECTING VPN DUE TO TIME LIMIT ===");

            // Show notification FIRST
            showTimeLimitReachedNotification();

            // Stop timer monitoring
            stopTimerMonitoring();

            // Clear timer preferences
            clearTimerPreferences();

            // ✅ CRITICAL FIX: Use the proper VPN stop mechanism
            // This is the same flow that happens when user manually disconnects

            if (mManagement != null) {
                Log.d(TAG, "Stopping VPN via management interface");
                try {
                    mManagement.stopVPN(false);
                } catch (Exception e) {
                    Log.e(TAG, "Error stopping via management: " + e.getMessage());
                }
            }

            // Force stop the OpenVPN process
            forceStopOpenVpnProcess();

            // Update VPN status
            VpnStatus.updateStateString("DISCONNECTED", "VPN disconnected - Time limit reached",
                    R.string.state_noprocess, ConnectionStatus.LEVEL_NOTCONNECTED);

            // ✅ CRITICAL: Call the proper cleanup method
            // This will handle all the necessary cleanup including stopping the VPN tunnel
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                try {
                    // This is the proper way to end the VPN service
                    endVpnService();

                    // Give it a moment to cleanup
                    new Handler(Looper.getMainLooper()).postDelayed(() -> {
                        try {
                            stopForeground(true);
                            stopSelf();
                            Log.d(TAG, "✅ VPN service stopped completely");
                        } catch (Exception ex) {
                            Log.e(TAG, "Error in final cleanup: " + ex.getMessage());
                        }
                    }, 1000);

                } catch (Exception e) {
                    Log.e(TAG, "Error in delayed disconnect: " + e.getMessage(), e);
                }
            }, 500);

        } catch (Exception e) {
            Log.e(TAG, "Error disconnecting VPN: " + e.getMessage(), e);
        }
    }

    private void showTimeLimitReachedNotification() {
        try {
            Log.d(TAG, "Showing time limit reached notification");

            // ✅ Create high-priority channel
            String channel = "vpn_time_limit_alert";

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationChannel chan = new NotificationChannel(
                        channel,
                        getAppName(this) + " VPN Time Alert",
                        NotificationManager.IMPORTANCE_HIGH
                );
                chan.setLightColor(Color.RED);
                chan.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
                chan.enableVibration(true);
                chan.setVibrationPattern(new long[]{0, 500, 250, 500});
                chan.setSound(null, null); // Use default sound

                NotificationManager service = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                if (service != null) {
                    service.createNotificationChannel(chan);
                }
            }

            NotificationManager mNotificationManager =
                    (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

            if (mNotificationManager == null) {
                Log.e(TAG, "❌ NotificationManager is null");
                return;
            }

            // ✅ Create intent to open app
            Intent launchIntent = getPackageManager()
                    .getLaunchIntentForPackage(getApplicationContext().getPackageName());

            if (launchIntent != null) {
                launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                launchIntent.putExtra("from_time_limit_notification", true);
            }

            PendingIntent pendingIntent = PendingIntent.getActivity(
                    this,
                    99999,
                    launchIntent != null ? launchIntent : new Intent(),
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            );

            Notification.Builder nbuilder = new Notification.Builder(this);

            nbuilder.setContentTitle("⏱️ VPN Time Limit Reached");
            nbuilder.setContentText("Your VPN session has ended. Tap to purchase more time.");

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                nbuilder.setStyle(new Notification.BigTextStyle()
                        .bigText("Your VPN session has ended. Purchase more time to continue using the VPN service."));
            }

            nbuilder.setSmallIcon(R.drawable.ic_notification);
            nbuilder.setContentIntent(pendingIntent);
            nbuilder.setAutoCancel(true);
            nbuilder.setOngoing(false);
            nbuilder.setOnlyAlertOnce(false);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                nbuilder.setPriority(Notification.PRIORITY_MAX);
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                nbuilder.setCategory(Notification.CATEGORY_ALARM);
                nbuilder.setVisibility(Notification.VISIBILITY_PUBLIC);
                nbuilder.setColor(Color.RED);
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nbuilder.setChannelId(channel);
                nbuilder.setTimeoutAfter(60000); // Keep for 60 seconds
            }

            // ✅ Add sound and vibration
            nbuilder.setDefaults(Notification.DEFAULT_ALL);

            Notification notification = nbuilder.build();

            // ✅ Use unique high ID
            mNotificationManager.notify(99999, notification);

            Log.d(TAG, "✅ Time limit notification posted successfully");

        } catch (Exception e) {
            Log.e(TAG, "❌ Error showing time limit notification: " + e.getMessage(), e);
        }
    }

    private void clearTimerPreferences() {
        try {
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

            // ✅ Log what we're clearing
            Log.d(TAG, "Clearing timer preferences");
            Log.d(TAG, "  Duration was: " + prefs.getInt(KEY_ALLOWED_DURATION, -1));
            Log.d(TAG, "  Start time was: " + prefs.getLong(KEY_CONNECTION_START_TIME, 0));
            Log.d(TAG, "  Pro user was: " + prefs.getBoolean(KEY_IS_PRO_USER, false));

            prefs.edit().clear().apply();

            Log.d(TAG, "✅ Timer preferences cleared");
        } catch (Exception e) {
            Log.e(TAG, "❌ Error clearing timer preferences: " + e.getMessage(), e);
        }
    }

    private void scheduleTimerAlarm(int allowedDurationSeconds) {
        try {
            if (alarmManager == null) {
                Log.e(TAG, "AlarmManager is null");
                return;
            }

            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            long startTime = prefs.getLong(KEY_CONNECTION_START_TIME, System.currentTimeMillis());

            // ✅ Calculate REMAINING time, not total duration
            long currentTime = System.currentTimeMillis();
            long elapsedSeconds = (currentTime - startTime) / 1000;
            long remainingSeconds = allowedDurationSeconds - elapsedSeconds;

            if (remainingSeconds <= 0) {
                Log.d(TAG, "⚠️ No remaining time, not scheduling alarm");
                return;
            }

            // ✅ Disconnect time is NOW + REMAINING seconds
            long disconnectTime = currentTime + (remainingSeconds * 1000L);

            Intent intent = new Intent(this, TimerAlarmReceiver.class);
            intent.setAction("DISCONNECT_VPN_TIMER");

            timerAlarmIntent = PendingIntent.getBroadcast(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
            );

            // Use exact alarm for critical disconnect
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                alarmManager.setExactAndAllowWhileIdle(
                        AlarmManager.RTC_WAKEUP,
                        disconnectTime,
                        timerAlarmIntent
                );
            } else {
                alarmManager.setExact(
                        AlarmManager.RTC_WAKEUP,
                        disconnectTime,
                        timerAlarmIntent
                );
            }

            prefs.edit().putBoolean(KEY_TIMER_ALARM_SET, true).apply();

            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
            Log.d(TAG, String.format("✅ Timer alarm scheduled: Remaining=%ds, Will disconnect at %s",
                    remainingSeconds, sdf.format(new Date(disconnectTime))));

        } catch (Exception e) {
            Log.e(TAG, "Error scheduling timer alarm: " + e.getMessage(), e);
        }
    }

    private void cancelTimerAlarm() {
        try {
            if (alarmManager != null && timerAlarmIntent != null) {
                alarmManager.cancel(timerAlarmIntent);
                Log.d(TAG, "✅ Timer alarm CANCELLED");
            } else {
                Log.d(TAG, "⚠️ Timer alarm already null, nothing to cancel");
            }

            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            prefs.edit().putBoolean(KEY_TIMER_ALARM_SET, false).apply();

        } catch (Exception e) {
            Log.e(TAG, "Error cancelling timer alarm: " + e.getMessage(), e);
        }
    }


    private void startTimerMonitoring() {
        try {
            // ✅ Don't start if not connected
            if (!isVpnConnected) {
                Log.d(TAG, "VPN not connected, skipping timer start");
                return;
            }

            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

            boolean isProUser = prefs.getBoolean(KEY_IS_PRO_USER, false);
            int allowedDuration = prefs.getInt(KEY_ALLOWED_DURATION, -1);

            if (isProUser || allowedDuration <= 0) {
                Log.d(TAG, "Timer monitoring not needed - Pro user or no duration set");
                return;
            }

            long startTime = prefs.getLong(KEY_CONNECTION_START_TIME, 0);

            // ✅ IMPORTANT: Use existing start time, don't create new one
            if (startTime == 0) {
                long now = System.currentTimeMillis();
                prefs.edit().putLong(KEY_CONNECTION_START_TIME, now).apply();
                Log.d(TAG, "⚠️ No start time found, setting to NOW: " + now);
                startTime = now;
            }

            // Check if timer has already expired
            long currentTime = System.currentTimeMillis();
            long elapsedSeconds = (currentTime - startTime) / 1000;
            long remainingSeconds = allowedDuration - elapsedSeconds;

            Log.d(TAG, String.format("📊 Timer Status: Elapsed=%ds, Total=%ds, Remaining=%ds",
                    elapsedSeconds, allowedDuration, remainingSeconds));

            if (remainingSeconds <= 0) {
                Log.d(TAG, "⚠️ Timer already expired, disconnecting immediately");
                disconnectDueToTimeLimit();
                return;
            }

            // Stop any existing timer before starting new one
            if (isTimerMonitoringActive) {
                Log.d(TAG, "Stopping existing timer before starting new one");
                stopTimerMonitoring();
            }

            isTimerMonitoringActive = true;

            // Acquire wake lock
            if (wakeLock != null && !wakeLock.isHeld()) {
                wakeLock.acquire();
                Log.d(TAG, "Wake lock acquired");
            }

            // Start timer checks
            if (timerHandler != null && timerCheckRunnable != null) {
                timerHandler.post(timerCheckRunnable);
                Log.d(TAG, "✅ Timer check runnable posted");
            }

            // ✅ CRITICAL: Schedule alarm with allowed duration (it will calculate remaining time)
            scheduleTimerAlarm(allowedDuration);

            Log.d(TAG, String.format("✅ Timer monitoring ACTIVE: %d seconds remaining", remainingSeconds));

        } catch (Exception e) {
            Log.e(TAG, "❌ Error starting timer monitoring: " + e.getMessage(), e);
        }
    }

    private void stopTimerMonitoring() {
        try {
            Log.d(TAG, "🛑 Stopping timer monitoring...");

            if (isTimerMonitoringActive) {
                isTimerMonitoringActive = false;

                if (timerHandler != null && timerCheckRunnable != null) {
                    timerHandler.removeCallbacks(timerCheckRunnable);
                    Log.d(TAG, "✅ Removed timer callbacks");
                }

                // ✅ ADD THIS - Remove ALL pending messages
                if (timerHandler != null) {
                    timerHandler.removeCallbacksAndMessages(null);
                }

                // Release wake lock
                if (wakeLock != null && wakeLock.isHeld()) {
                    try {
                        wakeLock.release();
                        Log.d(TAG, "✅ Wake lock released");
                    } catch (RuntimeException e) {
                        Log.e(TAG, "Error releasing wake lock: " + e.getMessage());
                    }
                }

                cancelTimerAlarm();
                Log.d(TAG, "✅ Timer monitoring STOPPED");
            }
        } catch (Exception e) {
            Log.e(TAG, "❌ Error stopping timer monitoring: " + e.getMessage(), e);
        }
    }

    
    @Override
    public void onDestroy() {
        Log.d(TAG, "🛑 ========== onDestroy CALLED ==========");

        // Stop timer
        stopTimerMonitoring();

        // Quit timer thread
        if (timerThread != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                timerThread.quitSafely();
            }
            timerThread = null;
        }

        // Stop VPN
        synchronized (mProcessLock) {
            if (mManagement != null) {
                try {
                    mManagement.stopVPN(true);
                } catch (Exception e) {
                    Log.e(TAG, "Error stopping VPN in onDestroy: " + e.getMessage());
                }
                mManagement = null;
            }

            if (mProcessThread != null) {
                mProcessThread.interrupt();
                mProcessThread = null;
            }
        }

        mOpenVPNThread = null;

        // Unregister receiver
        try {
            if (mDeviceStateReceiver != null) {
                this.unregisterReceiver(mDeviceStateReceiver);
            }
        } catch (IllegalArgumentException ignored) {
        }

        // Remove listeners
        VpnStatus.removeStateListener(this);
        VpnStatus.flushLog();

        // Clear flags
        isVpnConnected = false;
        mStarting = false;

        Log.d(TAG, "✅ onDestroy COMPLETED");

        super.onDestroy();
    }
    private String getTunConfigString() {
        // The format of the string is not important, only that
        // two identical configurations produce the same result
        String cfg = "TUNCFG UNQIUE STRING ips:";

        if (mLocalIP != null)
            cfg += mLocalIP.toString();
        if (mLocalIPv6 != null)
            cfg += mLocalIPv6;


        cfg += "routes: " + TextUtils.join("|", mRoutes.getNetworks(true)) + TextUtils.join("|", mRoutesv6.getNetworks(true));
        cfg += "excl. routes:" + TextUtils.join("|", mRoutes.getNetworks(false)) + TextUtils.join("|", mRoutesv6.getNetworks(false));
        cfg += "dns: " + TextUtils.join("|", mDnslist);
        cfg += "domain: " + mDomain;
        cfg += "mtu: " + mMtu;
        return cfg;
    }

    public ParcelFileDescriptor openTun() {

        //Debug.startMethodTracing(getExternalFilesDir(null).toString() + "/opentun.trace", 40* 1024 * 1024);

        Builder builder = new Builder();

        VpnStatus.logInfo(R.string.last_openvpn_tun_config);

        boolean allowUnsetAF = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && !mProfile.mBlockUnusedAddressFamilies;
        if (allowUnsetAF) {
            allowAllAFFamilies(builder);
        }

        if (mLocalIP == null && mLocalIPv6 == null) {
            VpnStatus.logError(getString(R.string.opentun_no_ipaddr));
            return null;
        }

        if (mLocalIP != null) {
            // OpenVPN3 manages excluded local networks by callback
            if (!VpnProfile.doUseOpenVPN3(this))
                addLocalNetworksToRoutes();
            try {
                builder.addAddress(mLocalIP.mIp, mLocalIP.len);
            } catch (IllegalArgumentException iae) {
                VpnStatus.logError(R.string.dns_add_error, mLocalIP, iae.getLocalizedMessage());
                return null;
            }
        }

        if (mLocalIPv6 != null) {
            String[] ipv6parts = mLocalIPv6.split("/");
            try {
                builder.addAddress(ipv6parts[0], Integer.parseInt(ipv6parts[1]));
            } catch (IllegalArgumentException iae) {
                VpnStatus.logError(R.string.ip_add_error, mLocalIPv6, iae.getLocalizedMessage());
                return null;
            }

        }


        for (String dns : mDnslist) {
            try {
                builder.addDnsServer(dns);
            } catch (IllegalArgumentException iae) {
                VpnStatus.logError(R.string.dns_add_error, dns, iae.getLocalizedMessage());
            }
        }

        String release = Build.VERSION.RELEASE;
        if ((Build.VERSION.SDK_INT == Build.VERSION_CODES.KITKAT && !release.startsWith("4.4.3")
                && !release.startsWith("4.4.4") && !release.startsWith("4.4.5") && !release.startsWith("4.4.6"))
                && mMtu < 1280) {
            VpnStatus.logInfo(String.format(Locale.US, "Forcing MTU to 1280 instead of %d to workaround Android Bug #70916", mMtu));
            builder.setMtu(1280);
        } else {
            builder.setMtu(mMtu);
        }

        Collection<IpAddress> positiveIPv4Routes = mRoutes.getPositiveIPList();
        Collection<IpAddress> positiveIPv6Routes = mRoutesv6.getPositiveIPList();

        if ("samsung".equals(Build.BRAND) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && mDnslist.size() >= 1) {
            // Check if the first DNS Server is in the VPN range
            try {
                IpAddress dnsServer = new IpAddress(new CIDRIP(mDnslist.get(0), 32), true);
                boolean dnsIncluded = false;
                for (IpAddress net : positiveIPv4Routes) {
                    if (net.containsNet(dnsServer)) {
                        dnsIncluded = true;
                    }
                }
                if (!dnsIncluded) {
                    String samsungwarning = String.format("Warning Samsung Android 5.0+ devices ignore DNS servers outside the VPN range. To enable DNS resolution a route to your DNS Server (%s) has been added.", mDnslist.get(0));
                    VpnStatus.logWarning(samsungwarning);
                    positiveIPv4Routes.add(dnsServer);
                }
            } catch (Exception e) {
                // If it looks like IPv6 ignore error
                if (!mDnslist.get(0).contains(":"))
                    VpnStatus.logError("Error parsing DNS Server IP: " + mDnslist.get(0));
            }
        }

        IpAddress multicastRange = new IpAddress(new CIDRIP("224.0.0.0", 3), true);

        for (IpAddress route : positiveIPv4Routes) {
            try {

                if (multicastRange.containsNet(route))
                    VpnStatus.logDebug(R.string.ignore_multicast_route, route.toString());
                else
                    builder.addRoute(route.getIPv4Address(), route.networkMask);
            } catch (IllegalArgumentException ia) {
                VpnStatus.logError(getString(R.string.route_rejected) + route + " " + ia.getLocalizedMessage());
            }
        }

        for (IpAddress route6 : positiveIPv6Routes) {
            try {
                builder.addRoute(route6.getIPv6Address(), route6.networkMask);
            } catch (IllegalArgumentException ia) {
                VpnStatus.logError(getString(R.string.route_rejected) + route6 + " " + ia.getLocalizedMessage());
            }
        }


        if (mDomain != null)
            builder.addSearchDomain(mDomain);

        String ipv4info;
        String ipv6info;
        if (allowUnsetAF) {
            ipv4info = "(not set, allowed)";
            ipv6info = "(not set, allowed)";
        } else {
            ipv4info = "(not set)";
            ipv6info = "(not set)";
        }

        int ipv4len;
        if (mLocalIP != null) {
            ipv4len = mLocalIP.len;
            ipv4info = mLocalIP.mIp;
        } else {
            ipv4len = -1;
        }

        if (mLocalIPv6 != null) {
            ipv6info = mLocalIPv6;
        }

        if ((!mRoutes.getNetworks(false).isEmpty() || !mRoutesv6.getNetworks(false).isEmpty()) && isLockdownEnabledCompat()) {
            VpnStatus.logInfo("VPN lockdown enabled (do not allow apps to bypass VPN) enabled. Route exclusion will not allow apps to bypass VPN (e.g. bypass VPN for local networks)");
        }
        if (mDomain != null) builder.addSearchDomain(mDomain);
        VpnStatus.logInfo(R.string.local_ip_info, ipv4info, ipv4len, ipv6info, mMtu);
        VpnStatus.logInfo(R.string.dns_server_info, TextUtils.join(", ", mDnslist), mDomain);
        VpnStatus.logInfo(R.string.routes_info_incl, TextUtils.join(", ", mRoutes.getNetworks(true)), TextUtils.join(", ", mRoutesv6.getNetworks(true)));
        VpnStatus.logInfo(R.string.routes_info_excl, TextUtils.join(", ", mRoutes.getNetworks(false)), TextUtils.join(", ", mRoutesv6.getNetworks(false)));
        VpnStatus.logDebug(R.string.routes_debug, TextUtils.join(", ", positiveIPv4Routes), TextUtils.join(", ", positiveIPv6Routes));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            setAllowedVpnPackages(builder);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            // VPN always uses the default network
            builder.setUnderlyingNetworks(null);
        }


        String session = mProfile.mName;
        if (mLocalIP != null && mLocalIPv6 != null)
            session = getString(R.string.session_ipv6string, session, mLocalIP, mLocalIPv6);
        else if (mLocalIP != null)
            session = getString(R.string.session_ipv4string, session, mLocalIP);
        else
            session = getString(R.string.session_ipv4string, session, mLocalIPv6);

        builder.setSession(session);

        // No DNS Server, log a warning
        if (mDnslist.size() == 0)
            VpnStatus.logInfo(R.string.warn_no_dns);

        mLastTunCfg = getTunConfigString();

        // Reset information
        mDnslist.clear();
        mRoutes.clear();
        mRoutesv6.clear();
        mLocalIP = null;
        mLocalIPv6 = null;
        mDomain = null;

        builder.setConfigureIntent(getGraphPendingIntent());

        try {
            //Debug.stopMethodTracing();
            ParcelFileDescriptor tun = builder.establish();
            if (tun == null)
                throw new NullPointerException("Android establish() method returned null (Really broken network configuration?)");
            return tun;
        } catch (Exception e) {
            VpnStatus.logError(R.string.tun_open_error);
            VpnStatus.logError(getString(R.string.error) + e.getLocalizedMessage());
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                VpnStatus.logError(R.string.tun_error_helpful);
            }
            return null;
        }

    }

    private boolean isLockdownEnabledCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return isLockdownEnabled();
        } else {
            /* We cannot determine this, return false */
            return false;
        }

    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private void allowAllAFFamilies(Builder builder) {
        builder.allowFamily(OsConstants.AF_INET);
        builder.allowFamily(OsConstants.AF_INET6);
    }

    private void addLocalNetworksToRoutes() {
        for (String net : NetworkUtils.getLocalNetworks(this, false)) {
            String[] netparts = net.split("/");
            String ipAddr = netparts[0];
            int netMask = Integer.parseInt(netparts[1]);
            if (ipAddr.equals(mLocalIP.mIp))
                continue;

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT && !mProfile.mAllowLocalLAN) {
                mRoutes.addIPSplit(new CIDRIP(ipAddr, netMask), true);

            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT && mProfile.mAllowLocalLAN)
                mRoutes.addIP(new CIDRIP(ipAddr, netMask), false);
        }

        // IPv6 is Lollipop+ only so we can skip the lower than KITKAT case
        if (mProfile.mAllowLocalLAN) {
            for (String net : NetworkUtils.getLocalNetworks(this, true)) {
                addRoutev6(net, false);
            }
        }


    }


    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private void setAllowedVpnPackages(Builder builder) {
        boolean profileUsesOrBot = false;

        for (Connection c : mProfile.mConnections) {
            if (c.mProxyType == Connection.ProxyType.ORBOT)
                profileUsesOrBot = true;
        }

        if (profileUsesOrBot)
            VpnStatus.logDebug("VPN Profile uses at least one server entry with Orbot. Setting up VPN so that OrBot is not redirected over VPN.");


        boolean atLeastOneAllowedApp = false;

        if (mProfile.mAllowedAppsVpnAreDisallowed && profileUsesOrBot) {
            try {
                builder.addDisallowedApplication(ORBOT_PACKAGE_NAME);
            } catch (PackageManager.NameNotFoundException e) {
                VpnStatus.logDebug("Orbot not installed?");
            }
        }

        for (String pkg : mProfile.mAllowedAppsVpn) {
            try {
                if (mProfile.mAllowedAppsVpnAreDisallowed) {
                    builder.addDisallowedApplication(pkg);
                } else {
                    if (!(profileUsesOrBot && pkg.equals(ORBOT_PACKAGE_NAME))) {
                        builder.addAllowedApplication(pkg);
                        atLeastOneAllowedApp = true;
                    }
                }
            } catch (PackageManager.NameNotFoundException e) {
                mProfile.mAllowedAppsVpn.remove(pkg);
                VpnStatus.logInfo(R.string.app_no_longer_exists, pkg);
            }
        }

        if (!mProfile.mAllowedAppsVpnAreDisallowed && !atLeastOneAllowedApp) {
            VpnStatus.logDebug(R.string.no_allowed_app, getPackageName());
            try {
                builder.addAllowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException e) {
                VpnStatus.logError("This should not happen: " + e.getLocalizedMessage());
            }
        }

        if (mProfile.mAllowedAppsVpnAreDisallowed) {
            VpnStatus.logDebug(R.string.disallowed_vpn_apps_info, TextUtils.join(", ", mProfile.mAllowedAppsVpn));
        } else {
            VpnStatus.logDebug(R.string.allowed_vpn_apps_info, TextUtils.join(", ", mProfile.mAllowedAppsVpn));
        }

        if (mProfile.mAllowAppVpnBypass) {
            builder.allowBypass();
            VpnStatus.logDebug("Apps may bypass VPN");
        }
    }

    public void addDNS(String dns) {
        mDnslist.add(dns);
    }

    public void setDomain(String domain) {
        if (mDomain == null) {
            mDomain = domain;
        }
    }

    /**
     * Route that is always included, used by the v3 core
     */
    public void addRoute(CIDRIP route, boolean include) {
        mRoutes.addIP(route, include);
    }

    public void addRoute(String dest, String mask, String gateway, String device) {
        CIDRIP route = new CIDRIP(dest, mask);
        boolean include = isAndroidTunDevice(device);

        IpAddress gatewayIP = new IpAddress(new CIDRIP(gateway, 32), false);

        if (mLocalIP == null) {
            VpnStatus.logError("Local IP address unset and received. Neither pushed server config nor local config specifies an IP addresses. Opening tun device is most likely going to fail.");
            return;
        }
        IpAddress localNet = new IpAddress(mLocalIP, true);
        if (localNet.containsNet(gatewayIP))
            include = true;

        if (gateway != null &&
                (gateway.equals("255.255.255.255") || gateway.equals(mRemoteGW)))
            include = true;


        if (route.len == 32 && !mask.equals("255.255.255.255")) {
            VpnStatus.logWarning(R.string.route_not_cidr, dest, mask);
        }

        if (route.normalise())
            VpnStatus.logWarning(R.string.route_not_netip, dest, route.len, route.mIp);

        mRoutes.addIP(route, include);
    }

    public void addRoutev6(String network, String device) {
        // Tun is opened after ROUTE6, no device name may be present
        boolean included = isAndroidTunDevice(device);
        addRoutev6(network, included);
    }

    public void addRoutev6(String network, boolean included) {
        String[] v6parts = network.split("/");

        try {
            Inet6Address ip = (Inet6Address) InetAddress.getAllByName(v6parts[0])[0];
            int mask = Integer.parseInt(v6parts[1]);
            mRoutesv6.addIPv6(ip, mask, included);

        } catch (UnknownHostException e) {
            VpnStatus.logException(e);
        }


    }

    private boolean isAndroidTunDevice(String device) {
        return device != null &&
                (device.startsWith("tun") || "(null)".equals(device) || VPNSERVICE_TUN.equals(device));
    }

    public void setMtu(int mtu) {
        mMtu = mtu;
    }

    public void setLocalIP(CIDRIP cdrip) {
        mLocalIP = cdrip;
    }

    public void setLocalIP(String local, String netmask, int mtu, String mode) {
        mLocalIP = new CIDRIP(local, netmask);
        mMtu = mtu;
        mRemoteGW = null;

        long netMaskAsInt = CIDRIP.getInt(netmask);

        if (mLocalIP.len == 32 && !netmask.equals("255.255.255.255")) {
            // get the netmask as IP

            int masklen;
            long mask;
            if ("net30".equals(mode)) {
                masklen = 30;
                mask = 0xfffffffc;
            } else {
                masklen = 31;
                mask = 0xfffffffe;
            }

            // Netmask is Ip address +/-1, assume net30/p2p with small net
            if ((netMaskAsInt & mask) == (mLocalIP.getInt() & mask)) {
                mLocalIP.len = masklen;
            } else {
                mLocalIP.len = 32;
                if (!"p2p".equals(mode))
                    VpnStatus.logWarning(R.string.ip_not_cidr, local, netmask, mode);
            }
        }
        if (("p2p".equals(mode) && mLocalIP.len < 32) || ("net30".equals(mode) && mLocalIP.len < 30)) {
            VpnStatus.logWarning(R.string.ip_looks_like_subnet, local, netmask, mode);
        }


        /* Workaround for Lollipop, it  does not route traffic to the VPNs own network mask */
        if (mLocalIP.len <= 31 && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            CIDRIP interfaceRoute = new CIDRIP(mLocalIP.mIp, mLocalIP.len);
            interfaceRoute.normalise();
            addRoute(interfaceRoute, true);
        }


        // Configurations are sometimes really broken...
        mRemoteGW = netmask;
    }

    public void setLocalIPv6(String ipv6addr) {
        mLocalIPv6 = ipv6addr;
    }


    @Override
    public void updateState(String state, String logmessage, int resid,
                            ConnectionStatus level, Intent intent) {
        Log.d(TAG, "📊 updateState: " + state + " -> " + level + " | msg: " + logmessage);

        doSendBroadcast(state, level);

        if (mProcessThread == null && !mNotificationAlwaysVisible)
            return;

        String channel = NOTIFICATION_CHANNEL_NEWSTATUS_ID;

        if (level == LEVEL_CONNECTED) {
            Log.d(TAG, "✅ VPN CONNECTED");

            isVpnConnected = true;
            mDisplayBytecount = true;
            mConnecttime = System.currentTimeMillis();
            mStarting = false; // ✅ Clear starting flag

            if (!runningOnAndroidTV())
                channel = NOTIFICATION_CHANNEL_BG_ID;

            // Start timer monitoring
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                if (isVpnConnected) {
                    startTimerMonitoring();
                }
            }, 2000);

        } else {
            mDisplayBytecount = false;

            if (level == ConnectionStatus.LEVEL_NOTCONNECTED) {
                Log.d(TAG, "❌ VPN DISCONNECTED");

                isVpnConnected = false;
                mStarting = false; // ✅ Clear starting flag

                stopTimerMonitoring();
                resetConnectionState();

                if (!isTimerMonitoringActive) {
                    clearTimerPreferences();
                }
            }
        }

        showNotification(VpnStatus.getLastCleanLogMessage(this),
                VpnStatus.getLastCleanLogMessage(this), channel, 0, level, intent);
    }


    @Override
    public void setConnectedVPN(String uuid) {
    }

    private void doSendBroadcast(String state, ConnectionStatus level) {
        Intent vpnstatus = new Intent();
        vpnstatus.setAction("de.blinkt.openvpn.VPN_STATUS");
        vpnstatus.putExtra("status", level.toString());
        vpnstatus.putExtra("detailstatus", state);
        sendBroadcast(vpnstatus, permission.ACCESS_NETWORK_STATE);
        sendMessage(state);
    }

    long c = Calendar.getInstance().getTimeInMillis();
    long time;
    int lastPacketReceive = 0;
    String seconds = "0", minutes, hours;

    @Override
    public void updateByteCount(long in, long out, long diffIn, long diffOut) {
        TotalTraffic.calcTraffic(this, in, out, diffIn, diffOut);
        if (mDisplayBytecount) {
            String netstat = String.format(getString(R.string.statusline_bytecount),
                    humanReadableByteCount(in, false, getResources()),
                    humanReadableByteCount(diffIn / OpenVPNManagement.mBytecountInterval, true, getResources()),
                    humanReadableByteCount(out, false, getResources()),
                    humanReadableByteCount(diffOut / OpenVPNManagement.mBytecountInterval, true, getResources()));


            showNotification(netstat, null, NOTIFICATION_CHANNEL_BG_ID, mConnecttime, LEVEL_CONNECTED, null);
            // byteIn = String.format("↓%2$s", getString(R.string.statusline_bytecount),
            //         humanReadableByteCount(in, false, getResources())) + " - " + humanReadableByteCount(diffIn / OpenVPNManagement.mBytecountInterval, false, getResources()) + "/s";
            // byteOut = String.format("↑%2$s", getString(R.string.statusline_bytecount),
            //         humanReadableByteCount(out, false, getResources())) + " - " + humanReadableByteCount(diffOut / OpenVPNManagement.mBytecountInterval, false, getResources()) + "/s";

            byteIn = String.valueOf(in);
            byteOut = String.valueOf(out);

            if(byteIn.isEmpty() ||byteIn.trim().length() == 0) byteIn = "0";
            if(byteOut.isEmpty() || byteOut.trim().length() == 0) byteOut = "0";

            time = Calendar.getInstance().getTimeInMillis() - c;
            lastPacketReceive = Integer.parseInt(convertTwoDigit((int) (time / 1000) % 60)) - Integer.parseInt(seconds);
//            seconds = convertTwoDigit((int) (time / 1000) % 60);
//            minutes = convertTwoDigit((int) ((time / (1000 * 60)) % 60));
//            hours = convertTwoDigit((int) ((time / (1000 * 60 * 60)) % 24));

            Calendar connectedOn = Calendar.getInstance();
            connectedOn.setTimeInMillis(c);

            @SuppressLint("SimpleDateFormat") DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            duration = dateFormat.format(connectedOn.getTime());
            lastPacketReceive = checkPacketReceive(lastPacketReceive);
            sendMessage(duration, String.valueOf(lastPacketReceive), byteIn, byteOut);
        }

    }

    public int checkPacketReceive(int value) {
        value -= 2;
        if (value < 0) return 0;
        else return value;
    }

    public String convertTwoDigit(int value) {
        if (value < 10) return "0" + value;
        else return value + "";
    }

    @Override
    public boolean handleMessage(Message msg) {
        Runnable r = msg.getCallback();
        if (r != null) {
            r.run();
            return true;
        } else {
            return false;
        }
    }

    public OpenVPNManagement getManagement() {
        return mManagement;
    }

    public String getTunReopenStatus() {
        String currentConfiguration = getTunConfigString();
        if (currentConfiguration.equals(mLastTunCfg)) {
            return "NOACTION";
        } else {
            String release = Build.VERSION.RELEASE;
            if (Build.VERSION.SDK_INT == Build.VERSION_CODES.KITKAT && !release.startsWith("4.4.3")
                    && !release.startsWith("4.4.4") && !release.startsWith("4.4.5") && !release.startsWith("4.4.6"))
                // There will be probably no 4.4.4 or 4.4.5 version, so don't waste effort to do parsing here
                return "OPEN_AFTER_CLOSE";
            else
                return "OPEN_BEFORE_CLOSE";
        }
    }

    public void requestInputFromUser(int resid, String needed) {
        VpnStatus.updateStateString("NEED", "need " + needed, resid, LEVEL_WAITING_FOR_USER_INPUT);
        showNotification(getString(resid), getString(resid), NOTIFICATION_CHANNEL_NEWSTATUS_ID, 0, LEVEL_WAITING_FOR_USER_INPUT, null);
    }


    public void trigger_sso(String info) {
        String channel = NOTIFICATION_CHANNEL_USERREQ_ID;
        String method = info.split(":", 2)[0];

        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        Notification.Builder nbuilder = new Notification.Builder(this);
        nbuilder.setAutoCancel(true);
        int icon = android.R.drawable.ic_dialog_info;
        nbuilder.setSmallIcon(icon);

        Intent intent;

        int reason;
        if (method.equals("CR_TEXT")) {
            String challenge = info.split(":", 2)[1];
            reason = R.string.crtext_requested;
            nbuilder.setContentTitle(getString(reason));
            nbuilder.setContentText(challenge);

            intent = new Intent();
            intent.setComponent(new ComponentName(this, getPackageName() + ".activities.CredentialsPopup"));

            intent.putExtra(EXTRA_CHALLENGE_TXT, challenge);

        } else {
            VpnStatus.logError("Unknown SSO method found: " + method);
            return;
        }

        // updateStateString trigger the notification of the VPN to be refreshed, save this intent
        // to have that notification also this intent to be set
        PendingIntent pIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
        VpnStatus.updateStateString("USER_INPUT", "waiting for user input", reason, LEVEL_WAITING_FOR_USER_INPUT, intent);
        nbuilder.setContentIntent(pIntent);


        // Try to set the priority available since API 16 (Jellybean)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN)
            jbNotificationExtras(PRIORITY_MAX, nbuilder);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            lpNotificationExtras(nbuilder, Notification.CATEGORY_STATUS);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            //noinspection NewApi
            nbuilder.setChannelId(channel);
        }

        @SuppressWarnings("deprecation")
        Notification notification = nbuilder.getNotification();


        int notificationId = channel.hashCode();

        mNotificationManager.notify(notificationId, notification);
    }

    //sending message to main activity
    private void sendMessage(String state) {
        Intent intent = new Intent("connectionState");
        intent.putExtra("state", state);
        OpenVPNService.state = state;
        LocalBroadcastManager.getInstance(getApplicationContext()).sendBroadcast(intent);
    }

    //sending message to main activity
    private void sendMessage(String duration, String lastPacketReceive, String byteIn, String byteOut) {
        Intent intent = new Intent("connectionState");
        intent.putExtra("duration", duration);
        intent.putExtra("lastPacketReceive", lastPacketReceive);
        intent.putExtra("byteIn", byteIn);
        intent.putExtra("byteOut", byteOut);
        LocalBroadcastManager.getInstance(getApplicationContext()).sendBroadcast(intent);
    }

    public class LocalBinder extends Binder {
        public OpenVPNService getService() {
            // Return this instance of LocalService so clients can call public methods
            return OpenVPNService.this;
        }
    }

    public static String getStatus() {//it will be call from mainactivity for get current status
        return state;
    }

    public static void setDefaultStatus() {
        state = "idle";
    }

    public boolean isConnected() {
        return flag;
    }
}
