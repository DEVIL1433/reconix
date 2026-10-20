package com.devil.reconix;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;

/** Dead-simple crash screen: no WebView, no Python, nothing that can crash.
 *  Shows the stack trace big enough to screenshot for diagnosis. */
public class CrashActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String trace = getIntent().getStringExtra("trace");
        if (trace == null || trace.isEmpty()) {
            trace = CrashLog.read(this);
        }
        TextView tv = new TextView(this);
        tv.setTextSize(13);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setPadding(36, 60, 36, 36);
        tv.setTextIsSelectable(true);
        tv.setText("RECONIX CRASHED\n\nScreenshot this whole screen for Gideon —\nit is the exact error.\n\n" + trace);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);
    }
}
