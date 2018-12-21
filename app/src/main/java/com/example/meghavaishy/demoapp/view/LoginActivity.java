package com.example.meghavaishy.demoapp.view;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.an.biometric.BiometricCallback;
import com.an.biometric.BiometricManager;
import com.example.meghavaishy.demoapp.R;
import com.example.meghavaishy.demoapp.utils.BiometricUtils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class LoginActivity extends AppCompatActivity implements View.OnClickListener {
    private KeyStore keyStore;
    private Button login;
    Cipher cipher;

    //  KEY_NAME is used to reference and find the generated key.
    private static final String KEY_NAME = "test";
    private BiometricPrompt mBiometricPrompt;
    private String mToBeSignedMessage;
    private static final String TAG = LoginActivity.class.getName();
    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;
    private RelativeLayout relativeLayout;
    private FingerPrintHandler helper;
    private TextView notCompatible;


    @TargetApi(Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        login = findViewById(R.id.login);
        relativeLayout = findViewById(R.id.activity_fingerprint);
        notCompatible = findViewById(R.id.desc);
        // setSupportActionBar(toolbar);
        login.setOnClickListener(this);
        if (BiometricUtils.currentBuild() == Build.VERSION_CODES.P) {
            login.setVisibility(View.VISIBLE);
            relativeLayout.setVisibility(View.GONE);
        } else {
            login.setVisibility(View.GONE);
            if (getSupportActionBar() != null) {
                getSupportActionBar().hide();
            }
            relativeLayout.setVisibility(View.VISIBLE);

            // For android version below P
            if (!BiometricUtils.isHardwareSupported(this)) {
                notCompatible.setText("Hardware Doesn't support");
//                Toast.makeText(this, "Hardware Doesn't support", Toast.LENGTH_SHORT).show();
            } else {
                //Check that the user has registered at least one fingerprint
                if (BiometricUtils.isFingerprintAvailable(this)) {
                    // Initializing both Android Keyguard Manager and Fingerprint Manager
                    KeyguardManager keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
                    fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
                    try {
                        generateKey();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    if (cipherInit()) {
                        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
                        helper = new FingerPrintHandler(this);
                        helper.startAuth(fingerprintManager, cryptoObject);
                    }
                } else {
                    Toast.makeText(this, "No registered FingerPrint of user available on Device", Toast.LENGTH_SHORT).show();
                }

            }
        }

    }


    @RequiresApi(api = Build.VERSION_CODES.P)
    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.login) {
            // For android version above P
            if (BiometricUtils.isBiometricPromptEnabled()) {
                // use Biometric Api
                displayBiometricPrompt();

            }
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean cipherInit() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }


        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }


    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey() throws Exception {
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        KeyGenerator keyGenerator;
        keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        keyStore.load(null);
        keyGenerator.init(new
                KeyGenParameterSpec.Builder(KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT |
                        KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(
                        KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build());
        keyGenerator.generateKey();
    }

    @RequiresApi(api = Build.VERSION_CODES.P)
    private void displayBiometricPrompt() {

        Signature signature;
        try {
            // Before generating a key pair, we have to check enrollment of biometrics on the device
            // But, there is no such method on new biometric prompt API
            // Note that this method will throw an exception if there is no enrolled biometric on the device
            KeyPair keyPair = generateKeyPair(KEY_NAME, true);
            // Send public key part of key pair to the server, this public key will be used for authentication
            mToBeSignedMessage = new StringBuilder()
                    .append(Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.URL_SAFE))
                    .append(":")
                    .append(KEY_NAME)
                    .append(":")
                    // Generated by the server to protect against replay attack
                    .append("12345")
                    .toString();

            // Generate keypair and initialize signature
            signature = initSignature(KEY_NAME);
        } catch (Exception e) {
            // to catch  Runtime exception like  At least one fingerprint must be enrolled to create keys requiring user authentication for every use
            throw new RuntimeException(e);
        }


        // Create biometricPrompt
        mBiometricPrompt = new BiometricPrompt.Builder(this)
                .setDescription("Description")
                .setTitle("Title")
                .setSubtitle("Subtitle")
                .setNegativeButton("Cancel", getMainExecutor(), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.i(TAG, "Cancel button clicked");
                    }
                })
                .build();

        CancellationSignal cancellationSignal = getCancellationSignal();
        BiometricPrompt.AuthenticationCallback authenticationCallback = getAuthenticationCallback();

        //display the fingerprint prompt and start listening on the fingerprint authentication events
        //CryptoObject to help authenticate the results of a fingerprint scan
        mBiometricPrompt.authenticate(new BiometricPrompt.CryptoObject(signature), cancellationSignal, getMainExecutor(), authenticationCallback);


    }

    private Signature initSignature(String keyName) throws Exception {

        KeyPair keyPair = getKeyPair(keyName);

        if (keyPair != null) {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
//            String signatureString = Base64.encodeToString(signature.sign(), Base64.URL_SAFE);
//            Toast.makeText(this,signatureString,Toast.LENGTH_SHORT).show();
            return signature;
        }
        return null;
    }

    private KeyPair getKeyPair(String keyName) throws Exception {
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyName)) {
            // Get public key
            PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            // Return a key pair
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }


    @RequiresApi(api = Build.VERSION_CODES.P)
    private KeyPair generateKeyPair(String keyName, boolean invalidatedByBiometricEnrollment) throws
            Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                //setUserAuthenticationRequired is true a developer can ensure that the generated key is usable only after a legitimate user has touched the fingerprint reader sensor
                .setUserAuthenticationRequired(true)
                // Generated keys will be invalidated if the biometric templates are added more to user device
                .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);

        //Generate a cryptographic key using initialize method
        keyPairGenerator.initialize(builder.build());

        return keyPairGenerator.generateKeyPair();


    }

    @RequiresApi(api = Build.VERSION_CODES.P)
    private BiometricPrompt.AuthenticationCallback getAuthenticationCallback() {

        return new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT || errorCode == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT) {
                    Toast.makeText(LoginActivity.this, errString, Toast.LENGTH_SHORT).show();
                }
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
            }

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                Log.i(TAG, "onAuthenticationSucceeded");
                super.onAuthenticationSucceeded(result);
                Signature signature = result.getCryptoObject().getSignature();
                try {
                    signature.update(mToBeSignedMessage.getBytes());
                    //  signature.sign() method resets the object into the same state like during the initSign(PrivateKey)
                    String signatureString = Base64.encodeToString(signature.sign(), Base64.URL_SAFE);
                    Log.i(TAG, "Message: " + mToBeSignedMessage);
                    Log.i(TAG, "Signature (Base64 EncodeD): " + signatureString);
                    Toast.makeText(getApplicationContext(), mToBeSignedMessage + ":" + signatureString, Toast.LENGTH_SHORT).show();
                } catch (SignatureException e) {
                    throw new RuntimeException();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
            }
        };

    }

    @RequiresApi(api = Build.VERSION_CODES.P)
    private CancellationSignal getCancellationSignal() {
        // With this cancel signal, we can cancel biometric prompt operation
        CancellationSignal cancellationSignal = new CancellationSignal();
        cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {
                //handle cancel result
                Log.i(TAG, "Canceled");
            }
        });
        return cancellationSignal;
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (helper != null)
            helper.cancel();
    }

    @Override
    protected void onStop() {
        super.onStop();
        finish();
    }
}
