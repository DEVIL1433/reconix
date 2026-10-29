package com.devil.reconix;

import android.content.Context;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

/** Writes crash details somewhere the user can actually show us:
 *  app external files (Android/data/com.devil.reconix/files/crash.txt). */
public class CrashLog {
    public static File file(Context ctx) {
        File dir = ctx.getExternalFilesDir(null);
        if (dir == null) dir = ctx.getFilesDir();
        return new File(dir, "crash.txt");
    }

    public static synchronized void write(Context ctx, String where, Throwable t) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(file(ctx), true))) {
            pw.println("==== " + where + " @ " + System.currentTimeMillis());
            t.printStackTrace(pw);
            pw.println();
        } catch (Exception ignored) {}

        // Cap: the log is read whole on the main thread at startup, so it
        // must never grow without bound. Over 64 KB, keep the newest 48 KB
        // starting at a clean entry boundary.
        try {
            File f = file(ctx);
            long max = 64L * 1024;
            if (f.length() > max) {
                int keep = 48 * 1024;
                byte[] buf = new byte[keep];
                int n = 0;
                try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f, "r")) {
                    raf.seek(f.length() - keep);
                    while (n < keep) {
                        int r = raf.read(buf, n, keep - n);
                        if (r < 0) break;
                        n += r;
                    }
                }
                int start = 0;
                while (start < n && buf[start] != '\n') start++;
                if (start < n) start++;
                try (java.io.FileOutputStream out = new java.io.FileOutputStream(f, false)) {
                    out.write(buf, start, n - start);
                }
            }
        } catch (Exception ignored) {}
    }

    public static String read(Context ctx) {
        try {
            File f = file(ctx);
            if (!f.exists()) return "";
            java.util.Scanner s = new java.util.Scanner(f, "UTF-8").useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        } catch (Exception e) {
            return "";
        }
    }
}
