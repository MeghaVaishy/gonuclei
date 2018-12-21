package com.example.meghavaishy.demoapp.view;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.support.annotation.RequiresApi;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.view.View;
import android.widget.TextView;

import com.example.meghavaishy.demoapp.R;

@TargetApi(Build.VERSION_CODES.M)
public class FingerPrintHandler extends FingerprintManager.AuthenticationCallback {

    private Context context;
    private CancellationSignal cancellationSignal;


    // Constructor
    public FingerPrintHandler(Context mContext) {
        context = mContext;
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        this.update("Fingerprint Authentication error\n" + errString, false);
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        this.update("Fingerprint Authentication help\n" + helpString, false);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        this.update("Fingerprint Authentication succeeded.", true);

    }

    @Override
    public void onAuthenticationFailed() {
        this.update("Fingerprint Authentication failed.", false);
    }

    public void update(String e, Boolean success) {
        TextView textView = (TextView) ((Activity) context).findViewById(R.id.errorText);
        textView.setText(e);
        if (success) {
            textView.setTextColor(ContextCompat.getColor(context, R.color.colorPrimaryDark));
        }
    }

    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {
        cancellationSignal = new CancellationSignal();
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
    }


    public void cancel() {
        if (cancellationSignal != null)
            cancellationSignal.cancel();
    }

}
