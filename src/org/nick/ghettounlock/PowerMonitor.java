
package org.nick.ghettounlock;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class PowerMonitor extends BroadcastReceiver {

    private static String TAG = PowerMonitor.class.getSimpleName();

    @Override
    public void onReceive(Context ctx, Intent intent) {
        Log.d(TAG, "received: " + intent);
        Log.d(TAG, "unlock on power connect: " + GhettoTrustAgent.isUnlockOnPowerConnect(ctx));

        if (!GhettoTrustAgent.isUnlockOnPowerConnect(ctx)) {
            return;
        }

        String action = intent.getAction();
        if (Intent.ACTION_POWER_CONNECTED.equals(action)) {
            Log.d(TAG, "Power connected. ");
            GhettoTrustAgent.sendGrantTrust(ctx, "GhettoTrustAgent::POWER_CONNECTED",
                    GhettoTrustAgentSettings.TRUST_DURATION_5MINS,
                    false);
        } else if (Intent.ACTION_POWER_DISCONNECTED.equals(action)) {
            Log.d(TAG, "Power disconnected");
            GhettoTrustAgent.sendRevokeTrust(ctx);
        }
    }
}
