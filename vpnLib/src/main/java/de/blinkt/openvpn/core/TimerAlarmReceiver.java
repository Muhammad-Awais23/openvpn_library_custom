package de.blinkt.openvpn.core;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * BroadcastReceiver that handles timer alarm for VPN disconnection
 * This ensures VPN disconnects even if the app is killed
 */
public class TimerAlarmReceiver extends BroadcastReceiver {
    private static final String TAG = "TimerAlarmReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "Timer alarm received - Time limit reached");

        if (intent != null && "DISCONNECT_VPN_TIMER".equals(intent.getAction())) {
            try {
                // Stop the OpenVPN service
                Intent serviceIntent = new Intent(context, OpenVPNService.class);
                serviceIntent.setAction(OpenVPNService.DISCONNECT_VPN);
                context.startService(serviceIntent);
                
                Log.d(TAG, "Sent disconnect intent to OpenVPNService");
                
            } catch (Exception e) {
                Log.e(TAG, "Error disconnecting VPN from alarm: " + e.getMessage(), e);
            }
        }
    }
}