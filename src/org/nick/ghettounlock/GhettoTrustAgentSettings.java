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

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.nick.ghettounlock.muscle.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

public class GhettoTrustAgentSettings extends Activity implements View.OnClickListener,
        CompoundButton.OnCheckedChangeListener, OnItemSelectedListener {

    private static final String TAG = GhettoTrustAgentSettings.class.getSimpleName();

    public static final int TRUST_DURATION_30SECS = 30 * 1000;

    public static final int TRUST_DURATION_5MINS = 5 * 60 * 1000;

    private static final int REQUEST_OPEN_DOCUMENT = 1;

    private CheckBox reportUnlockAttempts;
    private CheckBox managingTrust;
    private CheckBox unlockOnPowerConnect;

    private Spinner trustedSsidSpinner;

    private TextView trustedPubKey;

    private WifiManager wifiManager;
    private UsbManager usbManager;

    private List<String> ssids = new ArrayList<String>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.ghetto_trust_agent_settings);

        findViewById(R.id.enable_trust).setOnClickListener(this);
        findViewById(R.id.revoke_trust).setOnClickListener(this);
        findViewById(R.id.import_pub_key).setOnClickListener(this);
        findViewById(R.id.clear_pub_key).setOnClickListener(this);

        reportUnlockAttempts = (CheckBox) findViewById(R.id.report_unlock_attempts);
        reportUnlockAttempts.setOnCheckedChangeListener(this);

        managingTrust = (CheckBox) findViewById(R.id.managing_trust);
        managingTrust.setOnCheckedChangeListener(this);

        unlockOnPowerConnect = (CheckBox) findViewById(R.id.unlock_on_power_connect);
        unlockOnPowerConnect.setOnCheckedChangeListener(this);

        trustedSsidSpinner = (Spinner) findViewById(R.id.trusted_ssid_spinner);
        trustedSsidSpinner.setOnItemSelectedListener(this);

        trustedPubKey = (TextView) findViewById(R.id.trusted_pubkey);

        wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        usbManager = (UsbManager) getSystemService(Context.USB_SERVICE);
    }

    @Override
    protected void onResume() {
        super.onResume();

        reportUnlockAttempts.setChecked(GhettoTrustAgent.getReportUnlockAttempts(this));
        managingTrust.setChecked(GhettoTrustAgent.getIsManagingTrust(this));
        unlockOnPowerConnect.setChecked(GhettoTrustAgent.isUnlockOnPowerConnect(this));

        updateSsids();

        RSAPublicKey pubKey = GhettoTrustAgent.getPublicKey(this);
        if (pubKey != null) {
            trustedPubKey.setText(hashPubKey(pubKey));
        }
    }

    private static String hashPubKey(RSAPublicKey pubKey) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");

            return Hex.toHex(md.digest(pubKey.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private void updateSsids() {
        List<WifiConfiguration> wifis = wifiManager.getConfiguredNetworks();

        // Wifi is off
        if (wifis == null) {
            return;
        }

        ssids.clear();
        for (WifiConfiguration wifi : wifis) {
            ssids.add(wifi.SSID);
        }
        ArrayAdapter<String> ssidAdapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_dropdown_item_1line, ssids);

        trustedSsidSpinner.setAdapter(ssidAdapter);
        String trustedSsid = GhettoTrustAgent.getTrustedSsid(this);
        if (trustedSsid != null) {
            int idx = ssids.indexOf(trustedSsid);
            trustedSsidSpinner.setSelection(idx);
        }
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.enable_trust) {
            GhettoTrustAgent.sendGrantTrust(this, "GhettoTrustAgent", TRUST_DURATION_30SECS,
                    false);
        } else if (id == R.id.revoke_trust) {
            GhettoTrustAgent.sendRevokeTrust(this);
        } else if (id == R.id.import_pub_key) {
            Intent openIntent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            openIntent.setType("*/*");
            openIntent.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {
                    "application/octet-stream"
            });
            // hidden
            openIntent.putExtra("android.content.extra.SHOW_ADVANCED", true);
            startActivityForResult(openIntent, REQUEST_OPEN_DOCUMENT);
        } else if (id == R.id.clear_pub_key) {
            GhettoTrustAgent.setPublicKey(this, null);
            trustedPubKey.setText("");
        }
    }

    @Override
    public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
        if (buttonView == reportUnlockAttempts) {
            GhettoTrustAgent.setReportUnlockAttempts(this, isChecked);
        } else if (buttonView == managingTrust) {
            GhettoTrustAgent.setIsManagingTrust(this, isChecked);
        } else if (buttonView == unlockOnPowerConnect) {
            GhettoTrustAgent.setUnlockOnPowerConnect(this, isChecked);
        }
    }

    @Override
    public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
        if (parent == trustedSsidSpinner) {
            String oldSsid = GhettoTrustAgent.getTrustedSsid(this);
            String ssid = ssids.get(position);
            if (!ssid.equals(oldSsid)) {
                GhettoTrustAgent.setTrustedSsid(this, ssid);

                updateTrust(ssid);
            }
        }
    }

    private void updateTrust(String trustedSsid) {
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        if (wifiInfo == null) {
            return;
        }

        if (wifiInfo.getSSID() == null) {
            return;
        }

        if (wifiInfo.getSupplicantState() == SupplicantState.COMPLETED) {
            if (trustedSsid.equals(wifiInfo.getSSID())) {
                GhettoTrustAgent.sendGrantTrust(this, "GhettoTrustAgent", TRUST_DURATION_30SECS,
                        false);
            }
            else {
                Log.d(TAG, "Found insecure SSID: " + trustedSsid);
                GhettoTrustAgent.sendRevokeTrust(this);
            }
        } else {
            Log.d(TAG, "Disconnected from Wifi: " + trustedSsid);
            GhettoTrustAgent.sendRevokeTrust(this);
        }
    }

    @Override
    public void onNothingSelected(AdapterView<?> parent) {
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if (requestCode == REQUEST_OPEN_DOCUMENT) {
            if (resultCode == RESULT_OK) {
                X509Certificate cert = readCertificate(this, intent.getData());
                RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
                GhettoTrustAgent.setPublicKey(this, pubKey);

                Toast.makeText(this, "Successfully imported public key from certificate",
                        Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(
                        this,
                        "Failed to import public key",
                        Toast.LENGTH_LONG).show();
            }
        }
        super.onActivityResult(requestCode, resultCode, intent);
    }

    private static X509Certificate readCertificate(Context ctx, Uri uri) {
        InputStream in = null;
        try {
            in = ctx.getContentResolver().openInputStream(uri);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            return (X509Certificate) cf.generateCertificate(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

}
