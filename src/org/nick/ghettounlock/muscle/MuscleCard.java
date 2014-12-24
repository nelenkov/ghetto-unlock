package org.nick.ghettounlock.muscle;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.spongycastle.asn1.ASN1Encoding;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.DigestInfo;
import org.spongycastle.util.Arrays;

import android.nfc.tech.IsoDep;
import android.util.Log;

public class MuscleCard {

    private static final String TAG = MuscleCard.class.getSimpleName();

    private static final boolean DEBUG = true;

    private static final short SW_SUCCESS = (short) 0x9000;

    private static final String MUSCLE_AID = "A0 00 00 00 01 01";
    private static final String INPUT_OBJ_ID = "FF FF FF FF";
    private static final String OUTPUT_OBJ_ID = "FF FF FF FE";

    private static final String CERT_OBJECT_ID = "50 15 31 00";
    private static final int CERT_SIZE = 727;

    private static final int MAX_READ = 255;
    private static final int MAX_SEND = 255;

    private IsoDep tag;

    public MuscleCard(IsoDep tag) {
        this.tag = tag;
    }

    public void select() throws IOException {
        connect();

        String cmd = String.format("00 A4 04 00 %02x %s",
                byteLength(MUSCLE_AID), MUSCLE_AID);
        ResponseApdu rapdu = transceive(cmd);
        Log.d(TAG, "SELECT: " + rapdu.toString());
        checkSw(rapdu);
    }

    public boolean verifyPin(String pin) throws IOException {
        connect();

        String cmd = String.format("B0 42 01 00 %02x %s", pin.length(),
                Hex.toHex(pin.getBytes("ASCII")));
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "VERIFY PIN: " + rapdu.toString());
        }
        if (rapdu.getSW() != SW_SUCCESS) {
            Log.e(TAG, "Error reponse: " + Integer.toString(rapdu.getSW(), 16));
            // throw new MuscleException(rapdu.getSW());
            return false;
        }

        return true;
    }

    private void computeCryptInit() throws IOException {
        connect();

        // key 0x1, RSA_NOPAD
        String cmd = "B0 36 00 01 05 00 04 01 00 00 02";
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "COMPUTE CRYPT INIT: " + rapdu.toString());
        }
        checkSw(rapdu);
    }

    private void computeCryptFinal() throws IOException {
        connect();

        // data location: object (0x2)
        String cmd = "B0 36 00 03 01 02";
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "COMPUTE CRYPT FINAL: " + rapdu.toString());
        }
        checkSw(rapdu);
    }

    public void createObject(String id, int size, short readAcl,
            short writeAcl, short delAcl) throws IOException {
        connect();

        String cmd = String.format("B0 5A 00 00 0E %s %s %s %s %s", id,
                Hex.toHex(size), Hex.toHex(readAcl), Hex.toHex(writeAcl),
                Hex.toHex(delAcl));
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "CREATE OBJECT: " + rapdu.toString());
        }
        checkSw(rapdu);
    }

    public void updateObject(String objectId, int offset, byte[] data)
            throws IOException {
        connect();

        // len | data
        byte[] buff = new byte[data.length + 2];
        short dataLen = (short) data.length;
        buff[0] = (byte) ((dataLen >> 8) & 0xff);
        buff[1] = (byte) (dataLen & 0xff);
        System.arraycopy(data, 0, buff, 2, data.length);

        int chunkLen = MAX_SEND - 9;
        for (int i = 0; i < buff.length; i += chunkLen) {
            updateObjectChunk(objectId, offset + i, buff, i,
                    Math.min(buff.length - i, chunkLen));
        }
    }

    private void updateObjectChunk(String objectId, int offset, byte[] data,
            int dataOffset, int dataLen) throws IOException {
        connect();

        int lc = dataLen + 9;
        String cmd = String.format(
                "B0 54 00 00 %02x %s %s %02x %s",
                lc,
                objectId,
                Hex.toHex(offset),
                dataLen,
                Hex.toHex(Arrays.copyOfRange(data, dataOffset, dataOffset
                        + dataLen)));
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "UPDATE OBJECT: " + rapdu.toString());
        }
        checkSw(rapdu);
    }

    public byte[] readObject(String objectId, int offset, int dataLen)
            throws IOException {
        connect();

        int chunkLen = MAX_READ;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < dataLen; i += chunkLen) {
            byte[] chunk = readObjectChunk(objectId, offset + i,
                    Math.min(dataLen - i, chunkLen));
            baos.write(chunk);
        }

        return baos.toByteArray();
    }

    private byte[] readObjectChunk(String objectId, int offset, int dataLen)
            throws IOException {
        connect();

        // objectId | offset | dataLen | le
        String cmd = String.format("B0 56 00 00 09 %s %s %02x %02x", objectId,
                Hex.toHex(offset), dataLen, dataLen);
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "READ OBJECT: " + rapdu.toString());
        }
        checkSw(rapdu);

        return rapdu.getData();
    }

    private static byte[] createSha512EncryptionBlock(byte[] data, int keySize) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA512");
            byte[] digest = md.digest(data);
            // SHA512
            AlgorithmIdentifier sha512Aid = AlgorithmIdentifier
                    .getInstance("2.16.840.1.101.3.4.2.3");
            DigestInfo di = new DigestInfo(sha512Aid, digest);
            byte[] diDer = di.getEncoded(ASN1Encoding.DER);

            return padPkcs1(diDer, keySize);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // PKCS#1 padding
    private static byte[] padPkcs1(byte[] in, int keySize) {
        if (in.length > keySize) {
            throw new IllegalArgumentException("Data too long");
        }
        byte[] result = new byte[keySize / 8];

        result[0] = 0x0;
        result[1] = 0x01; // BT 1

        // PS
        for (int i = 2; i != result.length - in.length - 1; i++) {
            result[i] = (byte) 0xff;
        }

        // end of padding
        result[result.length - in.length - 1] = 0x00;
        // D
        System.arraycopy(in, 0, result, result.length - in.length, in.length);

        return result;
    }

    public byte[] sign(byte[] data) throws IOException {
        if (data.length == 0) {
            throw new IllegalArgumentException("Data must not be empty");
        }

        connect();

        computeCryptInit();

        // len | data => data length + 2
        int signatureLen = 2048 / 8;
        createObject(INPUT_OBJ_ID, signatureLen + 2, (short) 0x2, (short) 0x2,
                (short) 0x2);
        createObject(OUTPUT_OBJ_ID, signatureLen + 2, (short) 0x2, (short) 0x2,
                (short) 0x2);

        byte[] eb = createSha512EncryptionBlock(data, 2048);
        updateObject(OUTPUT_OBJ_ID, 0, eb);

        computeCryptFinal();

        // len | data => offset = 0x2
        String cmd = "B0 56 00 00 09 FF FF FF FF 00 00 00 02 FF FF";
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "READ OBJECT: " + rapdu.toString());
        }
        checkSw(rapdu);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(rapdu.getData());

        cmd = "B0 56 00 00 09 FF FF FF FF 00 00 01 01 01 01";
        rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "READ OBJECT: " + rapdu.toString());
        }
        checkSw(rapdu);
        baos.write(rapdu.getData());

        deleteObject(OUTPUT_OBJ_ID);

        return baos.toByteArray();
    }

    private void connect() throws IOException {
        if (!tag.isConnected()) {
            tag.connect();
        }
    }

    private void checkSw(ResponseApdu rapdu) {
        if (rapdu.getSW() != SW_SUCCESS) {
            Log.e(TAG, "Error reponse: " + Integer.toString(rapdu.getSW(), 16));
            throw new MuscleException(rapdu.getSW());
        }
    }

    private ResponseApdu transceive(String cmd) throws IOException {
        if (DEBUG) {
            Log.d(TAG, "--> " + cmd);
        }
        byte[] response = tag.transceive(Hex.fromHex(cmd));
        if (DEBUG) {
            Log.d(TAG, "<-- " + Hex.toHex(response));
        }

        return new ResponseApdu(response);
    }

    public void deleteObject(String id) throws IOException {
        connect();

        int len = byteLength(id);
        String cmd = String.format("B0 52 00 00 %02x %s", len, id);
        ResponseApdu rapdu = transceive(cmd);
        if (DEBUG) {
            Log.d(TAG, "DELETE OBJECT: " + rapdu.toString());
        }
        checkSw(rapdu);
    }

    public byte[] readSignerCertificate() throws IOException {
        return readObject(CERT_OBJECT_ID, 0, CERT_SIZE);
    }

    private static int byteLength(String id) {
        return id.replace(" ", "").length() / 2;
    }
}
