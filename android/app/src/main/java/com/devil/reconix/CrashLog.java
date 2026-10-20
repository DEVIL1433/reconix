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
