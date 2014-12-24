
package org.nick.ghettounlock;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Environment;
import android.util.Log;

import org.nick.ghettounlock.muscle.MuscleCard;

import java.io.File;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

public class GhettoNfcUnlockHandler implements NfcAdapter.NfcUnlockHandler {

    private static final String TAG = GhettoNfcUnlockHandler.class.getSimpleName();

    private RSAPublicKey pubKey;
    private String pin;

    private SecureRandom random = new SecureRandom();

    public GhettoNfcUnlockHandler(RSAPublicKey pubKey, String pin) {
        this.pubKey = pubKey;
        this.pin = pin;
    }

    @Override
    public boolean onUnlockAttempted(Tag tag) {
        Log.d(TAG, "Got unlock tag: " + tag);

        try {
            IsoDep isoDepTag = IsoDep.get(tag);
            if (isoDepTag == null) {
                Log.d(TAG, "Not an IsoDep tag: " + tag);

                return false;
            }
            isoDepTag.setTimeout(60 * 1000);

            MuscleCard msc = new MuscleCard(isoDepTag);

            msc.select();
            boolean pinValid = msc.verifyPin(pin);
            if (!pinValid) {
                Log.d(TAG, "Invalid PIN");

                return false;
            }

            // exportCertificate(msc);

            byte[] data = new byte[16];
            random.nextBytes(data);

            byte[] signature = msc.sign(data);

            Signature sig = Signature.getInstance("SHA512withRSA");
            sig.initVerify(pubKey);
            sig.update(data);
            boolean signatureValid = sig.verify(signature);
            Log.d(TAG, "Signature valid: " + signatureValid);

            if (signatureValid) {
                Log.d(TAG, "valided SC signature, granting trust");
                GhettoTrustAgent.sendGrantTrust(GhettoApp.getInstance(),
                        "GhettoTrustAgent::NFC::Signature",
                        GhettoTrustAgentSettings.TRUST_DURATION_30SECS,
                        false);

                return true;
            }

            return false;
        } catch (Exception e) {
            Log.e(TAG, "Error: " + e.getMessage(), e);

            return false;
        }
    }

    @SuppressWarnings("unused")
    private void exportCertificate(MuscleCard msc) throws Exception {
        byte[] cert = msc.readSignerCertificate();
        File certFile = new File(Environment.getExternalStorageDirectory(), "muscleCert.cer");
        FileOutputStream fos = new FileOutputStream(certFile);
        fos.write(cert);
        fos.flush();
        fos.close();
    }

}
