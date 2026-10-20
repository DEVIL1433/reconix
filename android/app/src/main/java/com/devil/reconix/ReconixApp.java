package com.devil.reconix;

import android.app.Application;
import android.content.Intent;

import java.io.PrintWriter;
import java.io.StringWriter;

/** Installs the crash handler before ANY component (activity or service)
 *  starts, so a crash can never again be a silent "keeps stopping":
 *  it is written to crash.txt AND shown on a plain crash screen. */
public class ReconixApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            try {
                CrashLog.write(getApplicationContext(), "uncaught", error);
                StringWriter sw = new StringWriter();
                error.printStackTrace(new PrintWriter(sw));
                Intent i = new Intent(getApplicationContext(), CrashActivity.class);
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                i.putExtra("trace", sw.toString());
                startActivity(i);
            } catch (Throwable ignored) {}
            android.os.Process.killProcess(android.os.Process.myPid());
            System.exit(10);
        });
    }
}
