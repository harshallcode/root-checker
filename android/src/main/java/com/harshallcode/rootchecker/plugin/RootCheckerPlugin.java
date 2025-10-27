package com.harshallcode.rootchecker.plugin;


import static androidx.core.content.ContextCompat.startActivity;
import static java.lang.System.getProperty;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;

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
            "/",
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
        var isRooted = checkRootMethod1() || checkRootMethod2() || checkRootMethod3() || checkRootMethod4() || checkRootMethod5() || checkRootMethod6() || checkRootMethod7() || checkRootMethod8();
        ret.put("isRooted", isRooted);
        call.resolve(ret);
    }

    private static boolean checkRootMethod1() {
        String buildTags = android.os.Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }

    private static boolean checkRootMethod2() {
        for (String path : DetectionConstants.ROOT_FILES) {
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
    public void isDeveloperModeEnable(PluginCall call) {
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
        ret.put("cpuArch", getProperty("os.arch"));
        call.resolve(ret);
    }

    @PluginMethod()
    public void openDeveloperSetting(PluginCall call) {
        startActivity(getContext(), new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS), null);
        call.resolve();
    }

    @PluginMethod()
    public void isADBEnabled(PluginCall call) {
        JSObject ret = new JSObject();
        int enabled = Settings.Global.getInt(getContext().getContentResolver(), Settings.Global.ADB_ENABLED, 0);
//        enabled=0;
        ret.put("isADBEnabled", enabled == 1);
        call.resolve(ret);
    }

    @PluginMethod()
    public void checkFridaPresence(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("isFridaDetected", detectNamedPipes() || detectSuspiciousThreads() || scanPorts());
        call.resolve(ret);
    }

    public static boolean detectNamedPipes() {
        String[] suspiciousPipes = {"frida", "gadget", "agent"};
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
        String host = "localhost";
        int flag = 0;
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
    public boolean checkRootMethod6() {
        return checkLdLibraryPathForSuspiciousEntries() || checkForDangerousProps() || checkXposedPresense() || checkMagiskIndicators();
    }

    public static boolean checkLdLibraryPathForSuspiciousEntries() {
        String ldLibraryPath = System.getenv("LD_LIBRARY_PATH");
        if (ldLibraryPath == null || ldLibraryPath.isEmpty()) {
            return false;
        }else{
            ldLibraryPath=ldLibraryPath.toLowerCase();
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
        Process process = null;
        BufferedReader reader = null;
        try {
            // Execute the 'getprop' command
            process = Runtime.getRuntime().exec("getprop");
            InputStream inputstream = process.getInputStream();
            if (inputstream == null) return null;

            // Use BufferedReader for efficient and safe line reading
            reader = new BufferedReader(new InputStreamReader(inputstream));
            StringBuilder output = new StringBuilder();
            String line;

            // Read all lines
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Wait for the process to complete (good practice)
            process.waitFor();

            return output.toString().split("\n");

        } catch (IOException | InterruptedException e) {
            // Log.e("RootDetection", "Error reading props", e);
            // It's crucial to return null/empty if the command fails,
            // as this could be due to a strict security manager.
            return null;
        } finally {
            // Explicitly close the reader and destroy the process
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {}
            }
            if (process != null) {
                // Ensure the process is destroyed, preventing resource leaks
                process.destroy();
            }
        }
    }

    public boolean checkForDangerousProps() {
        // Define properties and their "bad" values
        final Map<String, String> dangerousProps = new HashMap<>();
        dangerousProps.put("ro.debuggable", "1"); // Device is debuggable
        dangerousProps.put("ro.secure", "0"); // Device is insecure
        dangerousProps.put("ro.build.selinux", "0");
        // For properties where the existence alone is suspicious, use null as the "bad value" marker.
        dangerousProps.put("magisk.version", null); // Check for the mere existence
        dangerousProps.put("magisk.path", null);    // Check for the mere existence

//        boolean result = false;
        String[] lines = propsReader(); // Get all system properties

        if (lines == null) {
            return false;
        }
        for (String line : lines) {
            for (Map.Entry<String, String> entry : dangerousProps.entrySet()) {
                String key = entry.getKey();
                String badValue = entry.getValue();

                // 'getprop' prints lines like: [key]: [value]
                // If badValue is null we only want to know whether the property exists at all
                if (badValue == null) {
                    if (line.startsWith("[" + key + "]:")) {
                        Log.d("RootDetection", "Dangerous property detected (existence): " + key + " -> " + line);
                        return true;
                    }
                } else {
                    String checkString = "[" + key + "]: [" + badValue + "]";
                    if (line.contains(checkString)) {
                        Log.d("RootDetection", "Dangerous property detected: " + key + " = " + badValue);
                        return true;
                    }
                }
            }
            // Additional quick check: any mention of 'magisk' anywhere in getprop output is suspicious
            if (line.toLowerCase().contains("magisk")) {
                Log.d("RootDetection", "Magisk-related property/value detected in getprop output: " + line);
                return true;
            }
        }
        return false;
    }

    /**
     * Heuristic checks for Magisk / denylist presence. Looks for known Magisk paths,
     * module dirs and keywords in getprop output. This helps detect Magisk even when
     * some binaries are hidden by Magisk's denylist or hide features.
     */
    public static boolean checkMagiskIndicators() {
        // Common Magisk-related files and directories
        String[] magiskPaths = new String[] {
                "/sbin/.magisk",
                "/sbin/magisk",
                "/sbin/magiskinit",
                "/magisk/.core",
                "/magisk",
                "/data/adb/magisk",
                "/data/adb/modules",
                "/cache/.magisk",
                "/dev/.magisk",
                "/init.magisk.rc",
        };

        for (String p : magiskPaths) {
            try {
                File f = new File(p);
                if (f.exists()) {
                    Log.w("RootDetection", "Magisk file/directory found: " + p);
                    return true;
                }else{
                    Log.w("RootDetection", "Magisk file/directory not found: " + p);
                }
            } catch (Exception ignored) {
                Log.d("RootDetectionNew:",ignored.toString());
            }
        }

        // Check for Magisk strings in environment variables (LD*), and PATH
        try {
            String ld = System.getenv("LD_PRELOAD");
            if (ld != null && ld.toLowerCase().contains("magisk")) return true;
            String ldpath = System.getenv("LD_LIBRARY_PATH");
            if (ldpath != null && ldpath.toLowerCase().contains("magisk")) return true;
            String path = System.getenv("PATH");
            if (path != null && path.toLowerCase().contains("magisk")) return true;
        } catch (Exception ignored) {
        }

        // Check getprop output quickly for magisk/zygisk keywords
        String[] props = new RootCheckerPlugin().propsReader();
        if (props != null) {
            for (String line : props) {
                if (line != null && line.toLowerCase().contains("magisk")) {
                    Log.w("RootDetection", "Magisk keyword found in getprop: " + line);
                    return true;
                }
                if (line != null && line.toLowerCase().contains("zygisk")) {
                    Log.w("RootDetection", "Zygisk keyword found in getprop: " + line);
                    return true;
                }
            }
        }
        return false;
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
            Log.d("RootDetection:","Xposed version not found");
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
            if (clazzName != null && clazzName.contains("de.robv.android.xposed.XposedBridge")) {
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
            if (metaData != null && metaData.containsKey("xposedmodule")) {
                packages.add(installedPackage);
            }
        }
        return packages;
    }

    public boolean checkXposedPresense() {
        return getXposedVersion(getContext()) != null || isXposedInstallerAvailable(getContext()) || isXposedActive() ||
                !getInstalledXposedPackages(getContext()).isEmpty() || detectHookingFrameworks(getContext());
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
                // Use getApplicationInfo as it's lighter than getPackageInfo
                ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
                boolean isSystem = (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                // Only for logging: No real purpose, safe to remove
                 Log.d("RootDetection", "Found package: " + packageName + (isSystem ? " (System)" : " (User)"));
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Package not found, continue checking others
            }
        }
        return false;
    }

    private static boolean checkPtraceAttachment() {
        // Use try-with-resources for automatic closing
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Use startsWith for a minor optimization
                if (line.startsWith("TracerPid:")) {
                    // Extract and trim the PID part
                    String pidString = line.substring(10).trim();

                    try {
                        int tracerPid = Integer.parseInt(pidString);
                        if (tracerPid != 0) {
                             Log.w("RootDetection", "TracerPid detected: " + tracerPid);
                            return true;
                        }
                    } catch (NumberFormatException nfe) {
                        // Should not happen for a valid /proc/self/status file, but good for robustness
                        // Log.e("RootDetection", "NFE on TracerPid: " + pidString);
                        return false;
                    }
                }
            }
        } catch (IOException e) {
            // This is a common failure on modern Android or if the file is restricted,
            // so we don't necessarily treat it as a detection, but log the failure.
            // Log.e("RootDetection", "Error checking TracerPid: " + e.getMessage());
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
                "libzygisk_assistant.so", // Zygisk Assistant module [19]
                "libxposed_art.so",
                "libsubstrate.so",
                "libfrida-gadget.so",
                "libzygisk.so",
                "libshamiko.so",
                "libmagisk.so",
                "libwhale.so"
        ));

        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("r-xp") || line.contains("rwxp")) {
                    for (String lib : suspiciousLibraries) {
                        if (line.contains(lib)) {
                            Log.w("RootDetection", "Suspicious library in maps: " + lib);
                            return true;
                        }
                    }
                }
            }
        } catch (IOException e) {
            Log.e("RootDetection", "Error reading /proc/self/maps: " + e.getMessage());
        }
        return false;
    }

    //    Check Xposed framework file paths
    public static boolean checkRootMethod7() {
        try {
            List<String> abnormalProps = new ArrayList<>();

            for (String prop : DetectionConstants.BOOTLOADER_PROPS) {

                var propoer= getProperty(prop);
                if(propoer!=null) {
                    String value = Objects.requireNonNull(getProperty(prop)).toLowerCase();
                    if (value.contains("orange") || value.contains("unlocked")) {
                        abnormalProps.add(prop + ": " + value);
                    }
                }
            }
            String oemUnlockAllowed = getProperty("sys.oem_unlock_allowed");
            if ("1".equals(oemUnlockAllowed)) {
                abnormalProps.add("sys.oem_unlock_allowed: "+ oemUnlockAllowed);
            }

            return !abnormalProps.isEmpty();
        } catch (Exception e) {
//            XLog.e(TAG, "checkUnLock失败", e);
            return false;
        }
    }

    public static boolean checkRootMethod8() {
        // 1. Check if SELinux is set to Permissive (often a root side effect)
        try {
            Process p = Runtime.getRuntime().exec("getenforce");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String result = reader.readLine();
            p.waitFor();

            if (result != null && result.toLowerCase().contains("permissive")) {
                // Log.w("RootDetection", "SELinux is Permissive.");
                return true;
            }
        } catch (IOException | InterruptedException e) {
            // IOException may be thrown if getenforce command is blocked/not found.
            // It's not a root indicator itself, but an unusual system state.
        }

        // 2. Check if the app's SELinux context is altered (harder to cloak)
        // This is often done via native code, but a simple check is possible:
        try {
            Process p = Runtime.getRuntime().exec("cat /proc/self/attr/current");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String context = reader.readLine();
            p.waitFor();

            // Standard, non-root app contexts are typically like 'u:r:untrusted_app:s0'
            // If the context contains 'su' or 'magisk', it's a critical detection.
            if (context != null && (context.contains("magisk") || context.contains("zygisk"))) {
                // Log.w("RootDetection", "Suspicious SELinux context: " + context);
                return true;
            }
        } catch (IOException | InterruptedException e) {
            // Ignore
            Log.d("RootDetection:","Error in 8");
            Log.d("RootDetection:",e.toString());
        }

        return false;
    }
}