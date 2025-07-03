package com.harshallcode.rootchecker.plugin;


import static androidx.core.content.ContextCompat.startActivity;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
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
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Scanner;
import java.util.Set;

import dalvik.system.DexClassLoader;

@CapacitorPlugin(name = "RootChecker")
public class RootCheckerPlugin extends Plugin {

    private final RootChecker implementation = new RootChecker();
    static final String[] pathsThatShouldNotBeWritable = {
            "/etc",
            "/sbin",
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
    };

    @PluginMethod()
    public void checkRoot(PluginCall call) {
        JSObject ret = new JSObject();
        var isRooted = checkRootMethod1() || checkRootMethod2() || checkRootMethod3() || checkRootMethod4() || checkRootMethod5() || checkRootMethod7();
        ret.put("isRooted", isRooted);
        call.resolve(ret);
    }

    private static boolean checkRootMethod1() {
        String buildTags = android.os.Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }

    private static boolean checkRootMethod2() {
        String[] paths = {
                    "/data/adb/magisk.img",
                    "/data/adb/magisk",
                    "/data/local/bin/su",
                    "/data/local/su",
                    "/data/local/xbin/su",
                    "/sbin/.magisk",
                    "/sbin/magisk",//
                    "/sbin/su",
                    "/su/bin/su",
                    "/system/app/SuperSU.apk",
                    "/system/app/Superuser.apk",
                    "/system/app/Superuser.apk",
                    "/system/bin/.ext/.su",
                    "/system/bin/failsafe/su",
                    "/system/bin/su",
                    "/system/etc/init.d/99SuperSUDaemon",
                    "/system/sbin/su",
                    "/system/sd/xbin/su",
                    "/system/xbin/daemonsu",
                    "/system/xbin/su",
                    "/system/xbin/supolicy",
                };
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

    @PluginMethod()
    public void checkFridaPresence(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("isFridaDetected",  detectNamedPipes() || detectSuspiciousThreads() || scanPorts());
        call.resolve(ret);
    }

    public static boolean detectNamedPipes() {
        String[] suspiciousPipes = { "frida", "gadget", "agent" };
        File dir = new File("/proc/self/fd");

        for (File file : Objects.requireNonNull(dir.listFiles())) {
            String link = file.getAbsolutePath();
            for (String pipe : suspiciousPipes) {
                if (link.contains(pipe)) {
                    return true;
                }
            }
        }
        return false;
    }



    public static boolean detectSuspiciousThreads() {
        Set<Thread> threadSet = Thread.getAllStackTraces().keySet();
        for (Thread thread : threadSet) {
            String threadName = thread.getName();
            if (threadName.contains("frida") || threadName.contains("gadget") || threadName.contains("agent")) {
                return true;
            }
        }
        return false;
    }

    public static boolean scanPorts() {
        String host= "localhost";
        int flag=0;
        int[] suspiciousPorts = {27042, 27043}; // Common Frida ports
        for (int port : suspiciousPorts) {
            try (Socket socket = new Socket(host, port)) {
                return true;
            } catch (IOException ignored) {

            }
        }
        return false;
    }

    public static boolean scanStrings() {
        String[] suspiciousStrings = {"frida", "gadget", "agent"};
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                for (String str : suspiciousStrings) {
                    if (line.contains(str)) {
                        return true;
                    }
                }
            }
        } catch (IOException ignored) {

        }
        return false;
    }

//    New Methods
    public boolean checkRootMethod7(){
        return checkLdLibraryPathForSuspiciousEntries()||checkForDangerousProps()||checkXposedPresense();
    }
    public static boolean checkLdLibraryPathForSuspiciousEntries() {
        String ldLibraryPath = System.getenv("LD_LIBRARY_PATH");
        if (ldLibraryPath == null || ldLibraryPath.isEmpty()) {
            return false;
        }

        // Common indicators of injected libraries or tools
        String[] suspiciousKeywords = {
                "frida", "xposed", "magisk", "substrate", "zygisk",
                "/data/local/tmp", // Common temporary location for tools
                "/system/lib/asan", // Used for AddressSanitizer, but could be manipulated
        };

        for (String keyword : suspiciousKeywords) {
            if (ldLibraryPath.toLowerCase().contains(keyword.toLowerCase())) {
                return true; // Suspicious keyword found in LD_LIBRARY_PATH
            }
        }
        return false;
    }

    private String[] propsReader() {
        try {
            // Execute the 'getprop' command to list all system properties
            InputStream inputstream = Runtime.getRuntime().exec("getprop").getInputStream();
            if (inputstream == null) return null;
            // Read the entire output of the command
            String propVal = new Scanner(inputstream).useDelimiter("\\A").next();
            return propVal.split("\n"); // Split into individual property lines
        } catch (IOException | NoSuchElementException e) {
            return null;
        }
    }

    public boolean checkForDangerousProps() {
        // Define properties and their "bad" values
        final Map<String, String> dangerousProps = new HashMap<>();
        dangerousProps.put("ro.debuggable", "1"); // Device is debuggable
        dangerousProps.put("ro.secure", "0"); // Device is insecure

        boolean result = false;
        String[] lines = propsReader(); // Get all system properties

        if (lines == null){
            return false;
        }

        // Iterate through each property line and check against dangerous properties
        for (String line : lines) {
            for (String key : dangerousProps.keySet()) {
                if (line.contains(key)) {
                    String badValue = dangerousProps.get(key);
                    // The 'getprop' output format is typically "[key]: [value]" or "[key]: [value]\r"
                    // Need to match the value including brackets from getprop output
                    badValue = "[" + badValue + "]";
                    if (line.contains(badValue)) {
                        // QLog.v(key + " = " + badValue + " detected!"); // Log detection if QLog is available
                        result = true; // Dangerous property detected
                    }
                }
            }
        }
        return result;
    }

    public static Integer getXposedVersion(Context context) {
        try {
            File xposedBridge = new File("/system/framework/XposedBridge.jar");
            if (xposedBridge.exists()) {
                File optimizedDir = context.getDir("dex", Context.MODE_PRIVATE);
                DexClassLoader dexClassLoader = new DexClassLoader(
                        xposedBridge.getPath(),
                        optimizedDir.getPath(),
                        null,
                        ClassLoader.getSystemClassLoader()
                );
                Class<?> XposedBridge = dexClassLoader.loadClass("de.robv.android.xposed.XposedBridge");
                Method getXposedVersion = XposedBridge.getDeclaredMethod("getXposedVersion");
                if (!getXposedVersion.isAccessible()) getXposedVersion.setAccessible(true);
                return (Integer) getXposedVersion.invoke(null); // Invoke static method
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean isXposedInstallerAvailable(Context context) {
        try {
            ApplicationInfo appInfo = context.getPackageManager().getApplicationInfo("de.robv.android.xposed.installer", 0);
            return appInfo.enabled;
        } catch (PackageManager.NameNotFoundException ignored) {
            // Package not found
        }
        return false;
    }

    public static boolean isXposedActive() {
        StackTraceElement[] stackTraces = new Throwable().getStackTrace();
        for (StackTraceElement stackTrace : stackTraces) {
            final String clazzName = stackTrace.getClassName();
            if (clazzName!= null && clazzName.contains("de.robv.android.xposed.XposedBridge")) {
                return true; // XposedBridge class found in stack trace
            }
        }
        return false;
    }

    public static ArrayList<PackageInfo> getInstalledXposedPackages(Context context) {
        ArrayList<PackageInfo> packages = new ArrayList<>();
        PackageManager pm = context.getPackageManager();
        List<PackageInfo> installedPackages = pm.getInstalledPackages(PackageManager.GET_META_DATA);
        for (PackageInfo installedPackage : installedPackages) {
            Bundle metaData = installedPackage.applicationInfo.metaData;
            if (metaData!= null && metaData.containsKey("xposedmodule")) {
                packages.add(installedPackage);
            }
        }
        return packages;
    }

    public boolean checkXposedPresense(){
        return getXposedVersion(getContext())!=null||isXposedInstallerAvailable(getContext())||isXposedActive()||
                !getInstalledXposedPackages(getContext()).isEmpty()||detectHookingFrameworks(getContext());
    }

    // Known packages for root management or hooking frameworks
    private static final String[] KNOWN_HOOKING_PACKAGES = {
            "de.robv.android.xposed.installer", // Xposed Installer
            "com.saurik.cydia", // Cydia Substrate (less common on modern Android)
            "com.topjohnwu.magisk", // Magisk Manager itself
            "com.noshufou.android.su", // SuperSU
            "eu.chainfire.supersu", // SuperSU
            "com.koushikdutta.superuser", // Superuser
            // Additional packages can be added as new threats emerge
    };

    public static boolean detectHookingFrameworks(Context context) {
        boolean detected = false;

        // 1. Check for known hooking framework packages
        if (checkForKnownHookingPackages(context)) {
            System.out.println("RootDetection: Known hooking package detected.");
            detected = true;
        }

        // 3. Check for ptrace attachment, which indicates a debugger or instrumentation
        if (checkPtraceAttachment()) {
            System.out.println("RootDetection: Ptrace attachment detected.");
            detected = true;
        }

        // 4. Check for suspicious memory regions by analyzing /proc/self/maps.
        // This is a heuristic and more robust checks often require native code (NDK).
        if (checkSuspiciousMemoryMaps()) {
            System.out.println("RootDetection: Suspicious memory map detected.");
            detected = true;
        }

        return detected;
    }


    private static boolean checkForKnownHookingPackages(Context context) {
        PackageManager pm = context.getPackageManager();
        for (String packageName : KNOWN_HOOKING_PACKAGES) {
            try {
                pm.getPackageInfo(packageName, 0);
                System.out.println("RootDetection: Found package: " + packageName);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found, continue checking others
            }
        }
        return false;
    }
    private static boolean checkPtraceAttachment() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine())!= null) {
                if (line.startsWith("TracerPid:")) {
                    int tracerPid = Integer.parseInt(line.substring(10).trim());
                    if (tracerPid!= 0) {
                        System.out.println("RootDetection: TracerPid detected: " + tracerPid);
                        return true;
                    }
                }
            }
        } catch (IOException | NumberFormatException e) {
            System.err.println("RootDetection: Error checking TracerPid: " + e.getMessage());
        }
        return false;
    }

    private static boolean checkSuspiciousMemoryMaps() {
        Set<String> suspiciousLibraries = new HashSet<>(Arrays.asList(
                "libxposed_art.so", // Xposed framework library [49]
                "libsubstrate.so", // Cydia Substrate library [27]
                "libfrida-gadget.so", // Frida Gadget library [51]
                "libzygisk_next.so", // Zygisk Next module [18, 19]
                "libshamiko.so",     // Shamiko module [18, 19]
                "libzygisk_assistant.so" // Zygisk Assistant module [19]
        ));

        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine())!= null) {
                if (line.contains("r-xp")) {
                    for (String lib : suspiciousLibraries) {
                        if (line.contains(lib)) {
                            System.out.println("RootDetection: Suspicious library detected in memory maps: " + lib);
                            return true;
                        }
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("RootDetection: Error reading /proc/self/maps for suspicious libraries: " + e.getMessage());
        }
        return false;
    }
}