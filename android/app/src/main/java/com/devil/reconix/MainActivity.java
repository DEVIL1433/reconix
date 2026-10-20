package com.devil.reconix;

import android.Manifest;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.URLUtil;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class MainActivity extends Activity {
    private static final String VERSION_MARK = "3.20-v3r";
    private static final String APPV = "v1.4";
    private WebView web;
    private TextView splash;
    private volatile boolean booting = false;
    private int bootRetries = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Fix 4: ask for the notification permission so the running-engine
        // notification is actually visible on Android 13+.
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            try {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1001);
            } catch (Exception ignored) {}
        }

        FrameLayout root = new FrameLayout(this);
        splash = new TextView(this);
        splash.setTextSize(15);
        splash.setPadding(48, 96, 48, 48);
        String prior = CrashLog.read(this);
        String prevStage = readStage();
        boolean prevOk = new File(getFilesDir(), "boot-ok").exists();
        new File(getFilesDir(), "boot-ok").delete();
        splash.setText("RECONIX " + APPV + "\nstarting..."
                + (!prevOk && !prevStage.isEmpty()
                    ? "\n\nLast time it stopped at stage: " + prevStage : "")
                + (prior.isEmpty() ? ""
                    : "\n\n--- previous crash (screenshot this for Gideon) ---\n" + tail(prior, 1500)));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(splash);
        root.addView(scroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        try {
            web = new WebView(this);
        } catch (Throwable t) {
            CrashLog.write(this, "webview-create", t);
            splash.setText("RECONIX " + APPV + "\nWebView failed to start:\n" + t
                    + "\n\nScreenshot this for Gideon.");
            setContentView(root);
            return;
        }
        web.setVisibility(View.INVISIBLE);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setLoadWithOverviewMode(false);
        ws.setUseWideViewPort(false);
        // Triggers the mobile app shell in Reconix 3.20 (UA-gated server side).
        ws.setUserAgentString(ws.getUserAgentString() + " ReconixAndroid/3.20");
        ws.setBuiltInZoomControls(true);
        ws.setDisplayZoomControls(false);
        ws.setAllowFileAccess(false);
        ws.setAllowContentAccess(false);
        web.setWebViewClient(new WebViewClient() {
            // Fix 2b: if the engine dies mid-session, don't strand the user
            // on a dead error page — go back to the boot screen and restart.
            @Override
            public void onReceivedError(WebView view, WebResourceRequest req,
                                        WebResourceError err) {
                if (req.isForMainFrame() && bootRetries < 3) {
                    bootRetries++;
                    web.setVisibility(View.INVISIBLE);
                    stage("Engine unreachable — restarting (try "
                            + bootRetries + "/3)...");
                    startBoot();
                }
            }
        });
        // Fix 1: report exports (PDF/HTML/CSV/DOCX/HAR) are real downloads.
        // Route them to the system DownloadManager -> Downloads folder.
        web.setDownloadListener((url, userAgent, contentDisposition, mimeType, length) -> {
            try {
                String name = URLUtil.guessFileName(url, contentDisposition, mimeType);
                DownloadManager.Request req = new DownloadManager.Request(Uri.parse(url));
                req.setMimeType(mimeType);
                req.setTitle(name);
                req.setDescription("Reconix report");
                req.setNotificationVisibility(
                        DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                req.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, name);
                String cookies = CookieManager.getInstance().getCookie(url);
                if (cookies != null) req.addRequestHeader("Cookie", cookies);
                req.addRequestHeader("User-Agent", userAgent);
                ((DownloadManager) getSystemService(DOWNLOAD_SERVICE)).enqueue(req);
                Toast.makeText(this, "Downloading " + name + " to Downloads",
                        Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, "Download failed: " + e.getMessage(),
                        Toast.LENGTH_LONG).show();
            }
        });
        root.addView(web, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);

        startBoot();
    }

    private void startBoot() {
        if (booting) return;
        booting = true;
        new Thread(() -> {
            try {
                try {
                    stage("copying scanner files...");
                    ensureReconixCopied();
                    stage("starting engine...");
                    Intent svc = new Intent(this, ReconixService.class);
                    if (Build.VERSION.SDK_INT >= 26) {
                        startForegroundService(svc);
                    } else {
                        startService(svc);
                    }
                } catch (Throwable t) {
                    CrashLog.write(this, "boot", t);
                    stage("START FAILED:\n" + t + "\n\nScreenshot this for Gideon.");
                    return;
                }
                for (int i = 0; i < 90; i++) {
                    if (portOpen()) {
                        bootRetries = 0;
                        try (OutputStream o = new FileOutputStream(
                                new File(getFilesDir(), "boot-ok"))) {
                            o.write(1);
                        } catch (Exception ignored) {}
                        runOnUiThread(() -> {
                            web.setVisibility(View.VISIBLE);
                            web.loadUrl("http://127.0.0.1:8777/");
                        });
                        return;
                    }
                    if (i % 10 == 9) stage("waiting for engine... " + (i + 1) + "s");
                    try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                }
                String err = "";
                try {
                    File log = new File(new File(getFilesDir(), "reconix"), "server-error.log");
                    if (log.exists()) {
                        java.util.Scanner s = new java.util.Scanner(log, "UTF-8").useDelimiter("\\A");
                        err = s.hasNext() ? s.next() : "";
                    }
                } catch (Exception ignored) {}
                stage("Engine did not start in 90s.\n\n" + tail(err, 1500)
                        + "\nScreenshot this for Gideon.");
            } finally {
                booting = false;
            }
        }, "reconix-boot").start();
    }

    private static String tail(String s, int n) {
        return s.length() <= n ? s : s.substring(s.length() - n);
    }

    private void stage(String msg) {
        try (OutputStream o = new FileOutputStream(new File(getFilesDir(), "stage.txt"))) {
            o.write(msg.getBytes("UTF-8"));
        } catch (Exception ignored) {}
        runOnUiThread(() -> splash.setText("RECONIX " + APPV + "\n" + msg));
    }

    private String readStage() {
        try {
            File f = new File(getFilesDir(), "stage.txt");
            if (!f.exists()) return "";
            java.util.Scanner s = new java.util.Scanner(f, "UTF-8").useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        } catch (Exception e) {
            return "";
        }
    }

    private boolean portOpen() {
        try (Socket s = new Socket()) {
            s.connect(new java.net.InetSocketAddress("127.0.0.1", 8777), 500);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void ensureReconixCopied() throws IOException {
        File dest = new File(getFilesDir(), "reconix");
        File mark = new File(dest, ".apk-version");
        if (mark.exists()) {
            try (InputStream in = new java.io.FileInputStream(mark)) {
                byte[] buf = new byte[32];
                int n = in.read(buf);
                String v = new String(buf, 0, Math.max(n, 0), "UTF-8").trim();
                if (VERSION_MARK.equals(v)) return;
            } catch (Exception ignored) {}
        }
        copyAssetDir("reconix", dest);
        try (OutputStream out = new FileOutputStream(mark)) {
            out.write(VERSION_MARK.getBytes("UTF-8"));
        }
    }

    private void copyAssetDir(String assetPath, File dest) throws IOException {
        AssetManager am = getAssets();
        String[] items = am.list(assetPath);
        if (items == null || items.length == 0) {
            copyAssetFile(assetPath, dest);
            return;
        }
        if (!dest.exists()) dest.mkdirs();
        for (String item : items) {
            copyAssetDir(assetPath + "/" + item, new File(dest, item));
        }
    }

    private void copyAssetFile(String assetPath, File dest) throws IOException {
        File parent = dest.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        try (InputStream in = getAssets().open(assetPath);
             OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (web != null) web.destroy();
        super.onDestroy();
    }
}
