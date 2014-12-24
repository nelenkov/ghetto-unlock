package org.nick.ghettounlock;

import android.app.Application;

public class GhettoApp extends Application {

    private static GhettoApp instance;

    @Override
    public void onCreate() {
        super.onCreate();

        instance = this;
    }

    public static GhettoApp getInstance() {
        return instance;
    }
}
