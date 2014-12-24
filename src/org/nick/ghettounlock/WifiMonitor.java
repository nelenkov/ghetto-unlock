
package org.nick.ghettounlock;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.util.Log;

public class WifiMonitor extends BroadcastReceiver {

    private static final String TAG = WifiMonitor.class.getSimpleName();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (WifiManager.NETWORK_STATE_CHANGED_ACTION.equals(intent.getAction())) {
            NetworkInfo netInfo = (NetworkInfo) intent
                    .getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO);
            Log.d(TAG, "NetworkInfo: " + netInfo);
            if (netInfo.getState() == NetworkInfo.State.CONNECTED) {
                WifiInfo wifiInfo = (WifiInfo) intent
                        .getParcelableExtra(WifiManager.EXTRA_WIFI_INFO);
                String ssid = wifiInfo.getSSID();
                String secureSsid = GhettoTrustAgent.getTrustedSsid(context);
                if (secureSsid == null) {
                    return;
                }

                if (secureSsid.equals(ssid)) {
                    Log.d(TAG, "Found secure SSID: " + ssid);
                    GhettoTrustAgent.sendGrantTrust(context, "GhettoTrustAgent::WiFi",
                            GhettoTrustAgentSettings.TRUST_DURATION_5MINS,
                            false);
                }
                else {
                    Log.d(TAG, "Found insecure SSID: " + ssid);
                    GhettoTrustAgent.sendRevokeTrust(context);
                }
            }
        } else {
            Log.d(TAG, "Disconnected from WiFi, revoking trust");
            GhettoTrustAgent.sendRevokeTrust(context);
        }
    }
}
