package com.harshallcode.rootchecker.plugin;


import static androidx.core.content.ContextCompat.startActivity;

import android.content.Intent;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.scottyab.rootbeer.RootBeer;
import com.scottyab.rootbeer.util.QLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.NoSuchElementException;
import java.util.Scanner;

@CapacitorPlugin(name = "rootChecker")
public class rootCheckerPlugin extends Plugin {

    private final rootChecker implementation = new rootChecker();
    static final String[] pathsThatShouldNotBeWritable = {
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc",
    };

    @PluginMethod()
    public void checkRoot(PluginCall call) {
        JSObject ret = new JSObject();
        var isRooted = checkRootMethod1() || checkRootMethod2() || checkRootMethod3() || checkRootMethod4() || checkRootMethod5();
        ret.put("isRooted", isRooted);
        call.resolve(ret);
    }

    private static boolean checkRootMethod1() {
        String buildTags = android.os.Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }

    private static boolean checkRootMethod2() {
        String[] paths = {"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
                "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"};
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private static boolean checkRootMethod3() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            if (in.readLine() != null) return true;
            return false;
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) process.destroy();
        }
    }

    private boolean checkRootMethod4() {
        return new RootBeer(getContext()).isRooted();
    }

    private boolean checkRootMethod5() {
        boolean result = false;

        String[] lines = mountReader();

        if (lines == null) {
            return false;
        }
        String[] args = new String[0];
        int sdkVersion = android.os.Build.VERSION.SDK_INT;

        for (String line : lines) {

            args = line.split(" ");

            if ((sdkVersion <= android.os.Build.VERSION_CODES.M && args.length < 4)
                    || (sdkVersion > android.os.Build.VERSION_CODES.M && args.length < 6))
                QLog.e("Error formatting mount line: " + line);
        }

        String mountPoint;
        String mountOptions;

        if (sdkVersion > android.os.Build.VERSION_CODES.M) {
            mountPoint = args[2];
            mountOptions = args[5];
        } else {
            mountPoint = args[1];
            mountOptions = args[3];
        }

        for (String pathToCheck : pathsThatShouldNotBeWritable) {
            if (mountPoint.equalsIgnoreCase(pathToCheck)) {

                if (android.os.Build.VERSION.SDK_INT > android.os.Build.VERSION_CODES.M) {
                    mountOptions = mountOptions.replace("(", "");
                    mountOptions = mountOptions.replace(")", "");
                }
                for (String option : mountOptions.split(",")) {

                    if (option.equalsIgnoreCase("rw")) {
                        result = true;
                        break;
                    }
                }
            }
        }
        return result;
    }

    private String[] mountReader() {
        try {
            InputStream inputstream = Runtime.getRuntime().exec("cat /proc/mounts").getInputStream();
            if (inputstream == null)
                return null;
            String propVal = new Scanner(inputstream).useDelimiter("\\A").next();
            return propVal.split("\n");
        } catch (IOException | NoSuchElementException e) {
            QLog.e(e);
            return null;
        }
    }

    @PluginMethod()
    public void isDeveloperModeEnable(PluginCall call)  {
        JSObject ret = new JSObject();
        int devOptionsStatus = Settings.Secure.getInt(getContext().getContentResolver(),
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
        boolean isEnabled = (devOptionsStatus == 1);
//        isEnabled=false;
        ret.put("isEnabled", isEnabled);
        call.resolve(ret);
    }

    @PluginMethod()
    public void isEmulatorPresent(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("isEmulator", isEmulator());
        call.resolve(ret);
    }

    public static boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk".equals(Build.PRODUCT);
    }

    @PluginMethod()
    public static void getCpuArchitecture(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("cpuArch", System.getProperty("os.arch"));
        call.resolve(ret);
    }

    @PluginMethod()
    public void openDeveloperSetting(PluginCall call) {
        startActivity(getContext(),new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS),null);
        call.resolve();
    }

    @PluginMethod()
    public void isADBEnabled(PluginCall call) {
        JSObject ret = new JSObject();
        int enabled = Settings.Global.getInt(getContext().getContentResolver(), Settings.Global.ADB_ENABLED, 0);
//        enabled=0;
        ret.put("isADBEnabled", enabled==1);
        call.resolve(ret);
    }
}