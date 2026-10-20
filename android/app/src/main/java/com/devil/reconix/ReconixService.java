package com.devil.reconix;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import java.io.File;

public class ReconixService extends Service {
    private static final String CHANNEL = "reconix";
    private static final String TAG = "ReconixSvc";
    private Thread worker;
    private PowerManager.WakeLock wakeLock;

    @Override
    public void onCreate() {
        super.onCreate();
        // Fix 5: hold a partial wakelock (4h safety cap) so long scans are
        // not throttled when the screen sleeps. The permission was always
        // declared; v1.3 never actually used it.
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (pm != null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Reconix::engine");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire(4 * 60 * 60 * 1000L);
            }
        } catch (Exception e) {
            Log.e(TAG, "wakelock failed", e);
        }
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (Build.VERSION.SDK_INT >= 26 && nm != null) {
                nm.createNotificationChannel(new NotificationChannel(
                        CHANNEL, "Reconix scanner", NotificationManager.IMPORTANCE_LOW));
            }
            Intent open = new Intent(this, MainActivity.class);
            PendingIntent pi = PendingIntent.getActivity(this, 0, open,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            Notification.Builder b = Build.VERSION.SDK_INT >= 26
                    ? new Notification.Builder(this, CHANNEL)
                    : new Notification.Builder(this);
            Notification n = b.setContentTitle("Reconix is running")
                    .setContentText("Scanner engine on 127.0.0.1:8777")
                    .setSmallIcon(R.drawable.icon)
                    .setContentIntent(pi)
                    .build();
            // Android 14 requires the declared type + its permission; fall
            // back gracefully so a service-type problem can never kill the app.
            try {
                if (Build.VERSION.SDK_INT >= 29) {
                    startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
                } else {
                    startForeground(1, n);
                }
            } catch (Exception e) {
                Log.e(TAG, "typed startForeground failed, retrying untyped", e);
                try { startForeground(1, n); } catch (Exception e2) {
                    Log.e(TAG, "startForeground failed entirely; running unfettered", e2);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "onCreate notification setup failed", e);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Fix 2a: a finished worker must never block an engine restart.
        if (worker != null && !worker.isAlive()) worker = null;
        if (worker == null) {
            worker = new Thread(() -> {
                try {
                    if (!Python.isStarted()) {
                        Python.start(new AndroidPlatform(getApplicationContext()));
                    }
                    File dir = new File(getFilesDir(), "reconix");
                    Python.getInstance().getModule("launcher")
                            .callAttr("start_server", dir.getAbsolutePath());
                } catch (Throwable t) {
                    Log.e(TAG, "python engine failed", t);
                    CrashLog.write(this, "engine", t);
                } finally {
                    worker = null;
                }
            }, "reconix-server");
            worker.setDaemon(true);
            worker.start();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        } catch (Exception ignored) {}
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
