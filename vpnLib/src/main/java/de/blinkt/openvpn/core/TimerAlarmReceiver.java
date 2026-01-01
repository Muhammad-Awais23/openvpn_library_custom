package de.blinkt.openvpn.core;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * BroadcastReceiver that handles timer alarm for VPN disconnection
 * This ensures VPN disconnects even if the app is killed or in background
 */
public class TimerAlarmReceiver extends BroadcastReceiver {
    private static final String TAG = "TimerAlarmReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent != null && "DISCONNECT_VPN_TIMER".equals(intent.getAction())) {
            Log.d(TAG, "⏰ ========== TIMER ALARM RECEIVED ==========");
            Log.d(TAG, "Time limit reached - Disconnecting VPN");

            try {
                // ✅ CRITICAL: Use the proper VPN disconnect mechanism
                // Create intent that will be handled by OpenVPNService
                Intent disconnectIntent = new Intent(context, OpenVPNService.class);
                disconnectIntent.setAction(OpenVPNService.DISCONNECT_VPN); // Use the existing DISCONNECT_VPN action

                // Start the service to handle disconnection
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(disconnectIntent);
                    Log.d(TAG, "✅ Started foreground service with DISCONNECT_VPN");
                } else {
                    context.startService(disconnectIntent);
                    Log.d(TAG, "✅ Started service with DISCONNECT_VPN");
                }

                Log.d(TAG, "========== TIMER ALARM HANDLED ==========");

            } catch (Exception e) {
                Log.e(TAG, "❌ Error handling timer alarm: " + e.getMessage(), e);
            }
        } else {
            Log.d(TAG, "⚠️ Received intent with unexpected action: " +
                    (intent != null ? intent.getAction() : "null"));
        }
    }
}