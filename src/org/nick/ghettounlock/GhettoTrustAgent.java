/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package org.nick.ghettounlock;

import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.service.trust.TrustAgentService;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class GhettoTrustAgent extends TrustAgentService
        implements SharedPreferences.OnSharedPreferenceChangeListener {

    private static final String ACTION_GRANT_TRUST = "action.ghetoo_trust_agent.grant_trust";
    private static final String ACTION_REVOKE_TRUST = "action.ghetto_trust_agent.revoke_trust";

    private static final String EXTRA_MESSAGE = "extra.message";
    private static final String EXTRA_DURATION = "extra.duration";
    private static final String EXTRA_INITIATED_BY_USER = "extra.init_by_user";

    private static final String PREF_REPORT_UNLOCK_ATTEMPTS = "preference.report_unlock_attempts";
    private static final String PREF_MANAGING_TRUST = "preference.managing_trust";
    private static final String PREF_UNLOCK_ON_POWER = "preference.unlock_on_power";
    private static final String PREF_TRUSTED_SSID = "preference.trusted_ssid";
    private static final String PREF_PUB_KEY = "preferences.pub_key";

    private static final String TAG = "GhettoTrustAgent";

    private static final String[] NFC_TECHS = {
            IsoDep.class.getName(), NfcA.class.getName()
    };

    private static final String MUSCLE_PIN = "00000000";

    private LocalBroadcastManager localBroadcastManager;

    private NfcAdapter nfcAdapter;
    private GhettoNfcUnlockHandler unlockHandler;

    private DevicePolicyManager dpm;

    @Override
    public void onCreate() {
        super.onCreate();

        localBroadcastManager = LocalBroadcastManager.getInstance(this);

        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_GRANT_TRUST);
        filter.addAction(ACTION_REVOKE_TRUST);
        localBroadcastManager.registerReceiver(receiver, filter);

        setManagingTrust(getIsManagingTrust(this));

        PreferenceManager.getDefaultSharedPreferences(this)
                .registerOnSharedPreferenceChangeListener(this);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        installUnlockHandler();

        dpm = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        long maxTimeToLock = dpm.getMaximumTimeToLock(null);
        Log.d(TAG, "max time to lock: " + maxTimeToLock);
    }

    private void installUnlockHandler() {
        RSAPublicKey pubKey = getPublicKey(this);
        if (pubKey != null) {
            unlockHandler = new GhettoNfcUnlockHandler(pubKey, MUSCLE_PIN);
            nfcAdapter.addNfcUnlockHandler(unlockHandler, NFC_TECHS);
        }
    }

    @Override
    public void onTrustTimeout() {
        super.onTrustTimeout();
        Toast.makeText(this, "onTrustTimeout(): timeout expired", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onUnlockAttempt(boolean successful) {
        if (getReportUnlockAttempts(this)) {
            Toast.makeText(this, "onUnlockAttempt(successful=" + successful + ")",
                    Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public boolean onSetTrustAgentFeaturesEnabled(Bundle options) {
        Log.v(TAG, "Policy options received: " + options.getStringArrayList(KEY_FEATURES));

        return true; // inform DPM that we support it
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        localBroadcastManager.unregisterReceiver(receiver);
        PreferenceManager.getDefaultSharedPreferences(this)

                .unregisterOnSharedPreferenceChangeListener(this);

        uninstallUnlockHandler();
    }

    private void uninstallUnlockHandler() {
        if (unlockHandler != null) {
            nfcAdapter.removeNfcUnlockHandler(unlockHandler);
        }
    }

    private BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (ACTION_GRANT_TRUST.equals(action)) {
                try {
                    grantTrust(intent.getStringExtra(EXTRA_MESSAGE),
                            intent.getLongExtra(EXTRA_DURATION, 0),
                            intent.getBooleanExtra(EXTRA_INITIATED_BY_USER, false));
                } catch (IllegalStateException e) {
                    Toast.makeText(context,
                            "IllegalStateException: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            } else if (ACTION_REVOKE_TRUST.equals(action)) {
                revokeTrust();
            }
        }
    };

    public static void sendGrantTrust(Context context,
            String message, long durationMs, boolean initiatedByUser) {
        Intent intent = new Intent(ACTION_GRANT_TRUST);
        intent.putExtra(EXTRA_MESSAGE, message);
        intent.putExtra(EXTRA_DURATION, durationMs);
        intent.putExtra(EXTRA_INITIATED_BY_USER, initiatedByUser);
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
    }

    public static void sendRevokeTrust(Context context) {
        Intent intent = new Intent(ACTION_REVOKE_TRUST);
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
    }

    public static void setReportUnlockAttempts(Context context, boolean enabled) {
        SharedPreferences sharedPreferences = PreferenceManager
                .getDefaultSharedPreferences(context);
        sharedPreferences.edit().putBoolean(PREF_REPORT_UNLOCK_ATTEMPTS, enabled).apply();
    }

    public static boolean getReportUnlockAttempts(Context context) {
        SharedPreferences sharedPreferences = PreferenceManager
                .getDefaultSharedPreferences(context);
        return sharedPreferences.getBoolean(PREF_REPORT_UNLOCK_ATTEMPTS, false);
    }

    public static void setIsManagingTrust(Context context, boolean enabled) {
        SharedPreferences sharedPreferences = PreferenceManager
                .getDefaultSharedPreferences(context);
        sharedPreferences.edit().putBoolean(PREF_MANAGING_TRUST, enabled).apply();
    }

    public static boolean getIsManagingTrust(Context context) {
        SharedPreferences sharedPreferences = PreferenceManager
                .getDefaultSharedPreferences(context);
        return sharedPreferences.getBoolean(PREF_MANAGING_TRUST, false);
    }

    public static void setUnlockOnPowerConnect(Context ctx, boolean unlock) {
        PreferenceManager
                .getDefaultSharedPreferences(ctx).edit().putBoolean(PREF_UNLOCK_ON_POWER, unlock)
                .commit();
    }

    public static boolean isUnlockOnPowerConnect(Context ctx) {
        return PreferenceManager
                .getDefaultSharedPreferences(ctx).getBoolean(PREF_UNLOCK_ON_POWER, false);
    }

    public static String getTrustedSsid(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getString(PREF_TRUSTED_SSID,
                null);
    }

    public static void setTrustedSsid(Context ctx, String ssid) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putString(PREF_TRUSTED_SSID, ssid).commit();
    }

    public static void setPublicKey(Context ctx, RSAPublicKey pubKey) {
        String pubKeyStr = pubKey == null ? null : Base64.encodeToString(pubKey.getEncoded(),
                Base64.DEFAULT);
        PreferenceManager
                .getDefaultSharedPreferences(ctx).edit().putString(PREF_PUB_KEY, pubKeyStr)
                .commit();
    }

    public static RSAPublicKey getPublicKey(Context ctx) {
        String pubKeyStr = PreferenceManager
                .getDefaultSharedPreferences(ctx).getString(PREF_PUB_KEY, null);
        if (pubKeyStr == null) {
            return null;
        }

        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(pubKeyStr.getBytes(
                    "UTF-8"), Base64.DEFAULT));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKey pubKey =
                    (RSAPublicKey) kf.generatePublic(keySpec);

            return pubKey;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        if (PREF_MANAGING_TRUST.equals(key)) {
            setManagingTrust(getIsManagingTrust(this));
        } else if (PREF_PUB_KEY.equals(key)) {
            RSAPublicKey pubKey = getPublicKey(this);
            if (pubKey != null) {
                installUnlockHandler();
            } else {
                uninstallUnlockHandler();
            }
        }
    }
}
