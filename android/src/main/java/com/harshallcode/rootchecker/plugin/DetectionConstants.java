package com.harshallcode.rootchecker.plugin;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DetectionConstants {
    public static final String ZYGISK_PATH = "/data/adb/zy";
    public static String AP_PACKAGE_PATH = "/data/data/me.bmax.apatch";
    public static String SDCARD_DOWNLOAD_PATH = "/sdcard/Download";
    public static String SDCARD_ANDROID_PATH = "/sdcard/Android/";
    public static String DATA_LOCAL_TMP_PATH = "/data/local/tmp";
    public static final String[] FINGERPRINT_REGIONS = {
            "build", "bootimage", "odm", "product", "system_ext", "system", "vendor"
    };
    public static final String KEYCHAIN_DIR = "/data/misc/keychain";
    public static final String PUBKEY_BLACKLIST_FILE = "/data/misc/keychain/pubkey_blacklist.txt";
    public static final String SERIAL_BLACKLIST_FILE = "/data/misc/keychain/serial_blacklist.txt";
    public static final Map<String, String> PATH_MAPPINGS = new HashMap<String, String>() {{
        put("/sdcard/Android/data/.nomedia", "SDADN");
        put("/sdcard/Android/data/com.google.android.gms", "SDADC");
        put("/sdcard/", "SD");
        put("/storage/emulated/0", "SD0");
    }};
    public static final List<String> MOUNT_KEYWORDS = Arrays.asList(
            "apatch",
            "ksu",
            "magisk",
            "supersu",
            "xposed",
            "edxposed",
            "lsposed"
    );

    public static final List<String> MAPS_KEYWORDS = Arrays.asList(
            "lspatch",
            "xposed",
            "edxposed",
            "lsposed",
            "riru",
            "zygisk",
            "magisk",
            "epic",
            "taichi",
            "virtualapp",
            "substratego",
            "dexposed"
    );
    /**
     * 模拟器共享文件夹路径列表
     */
    public static final String[] EMULATOR_MOUNT_PATHS = {
            "/mnt/shared/Sharefolder",    // 通用共享文件夹
            "/tiantian.conf",             // 天天模拟器
            "/data/share1",               // 通用共享目录
            "/hardware_device.conf",      // 硬件配置文件
            "/mnt/shared/products",       // 共享产品目录
            "/mumu_hardware.conf",        // MUMU模拟器
            "/Andy.conf",                 // Andy模拟器
            "/mnt/windows/BstSharedFolder", // BlueStacks
            "/bst.conf",                  // BlueStacks配置
            "/mnt/shared/Applications",   // 共享应用目录
            "/ld.conf",                    // LD模拟器
            "vboxsf",                      //virtualbox
            "docker"
    };
    /**
     * 检测这些属性的值是否异常。这是用于检测是否设备unlock
     */
    public static final String[] BOOTLOADER_PROPS = {
            "ro.boot.verifiedbootstate",
            "ro.secureboot.lockstate",
            "vendor.boot.vbmeta.device_state",
            "vendor.boot.verifiedbootstate",
            "ro.boot.vbmeta.device_state",
            "ro.boot.flash.locked"
    };
    /**
     * 模拟器的prop特征
     */
    public static final String[] QEMU_PROPS = {
            "ro.kernel.qemu.avd_name",
            "ro.kernel.qemu.gltransport",
            "ro.kernel.qemu.opengles.version",
            "ro.kernel.qemu.uirenderer",
            "ro.kernel.qemu.vsync",
            "ro.qemu.initrc",
            "init.svc.qemu-props",
            "qemu.adb.secure",
            "qemu.cmdline",
            "qemu.hw.mainkeys",
            "qemu.logcat",
            "ro.adb.qemud",
            "qemu.sf.fake_camera",
            "qemu.sf.lcd_density",
            "qemu.timezone",
            "init.svc.goldfish-logcat",
            "ro.boottime.goldfish-logcat",
            "ro.hardware.audio.primary",
            "init.svc.ranchu-net",
            "init.svc.ranchu-setup",
            "ro.boottime.ranchu-net",
            "ro.boottime.ranchu-setup",
            "init.svc.droid4x",
            "init.svc.noxd",
            "init.svc.qemud",
            "init.svc.goldfish-setup",
            "init.svc.goldfish-logcat",
            "init.svc.ttVM_x86-setup",
            "vmos.browser.home",
            "vmos.camera.enable",
            "ro.trd_yehuo_searchbox",
            "init.svc.microvirtd",
            "init.svc.vbox86-setup",
            "ro.ndk_translation.version",
            "redroid.width",
            "redroid.height",
            "redroid.fps",
            "ro.rf.vmname"
    };

    public static List<String> XPOSED_PATHS = Arrays.asList(
            "/sbin/.magisk/modules/riru_lsposed",
            "/data/adb/lspd",
            "/sbin/.magisk/modules/zygisk_lsposed",
            "/sbin/.magisk/modules/riru_edxposed",
            "/data/misc/riru/modules/edxp",
            "/data/adb/riru/modules/edxp.prop",
            "/sbin/.magisk/modules/taichi",
            "/data/misc/taichi",
            "/sbin/.magisk/modules/dreamland",
            "/data/misc/riru/modules/dreamland",
            "/data/adb/riru/modules/dreamland",
            "/system/bin/app_process.orig",
            "/system/xposed.prop",
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib/libxposed_art.so.no_orig",
            "/system/lib64/libxposed_art.so",
            "/system/lib64/libxposed_art.so.no_orig",
            "/system/bin/app_process_zposed",
            "/system/framework/ZposedBridge.jar",
            "/system/lib/libzposed_art.so"
    );

    public static final String[] ROOT_PACKAGES = {
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.fox2code.mmm",
            "io.github.vvb2060.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot",
            "io.github.huskydg.magisk",
            "me.weishu.kernelsu",
            "me.bmax.apatch"
    };

    public static final String[] ROOT_FILES = {
            "/apex/com.android.art/bin/su",
            "/apex/com.android.runtime/bin/su",
            "/cache/.disable_magisk",
            "/cache/magisk.log",
            "/cache/magisk.log.bak",
            "/cache/su",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/shamiko",
            "/data/adb/zydisksu",
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/data/magisk.apk",
            "/data/su",
            "/dev/com.koushikdutta.superuser.daemon",
            "/dev/magisk/img",
            "/dev/su",
            "/odm/bin/su",
            "/product/bin/su",
            "/sbin/.magisk",
            "/sbin/.mianju",
            "/sbin/magisk",
            "/sbin/magisk32",
            "/sbin/magiskinit",
            "/sbin/magiskpolicy",
            "/sbin/su",
            "/sbin/supolicy",
            "/su/bin/su",
            "/system/.supersu",
            "/system/addon.d/99-magisk.sh",
            "/system/app/Superuser.apk",
            "/system/app/SuperUser/SuperUser.apk",
            "/system/bin/.ext/.su",
            "/system/bin/.ext/su",
            "/system/bin/.hid/su",
            "/system/bin/cph_su",
            "/system/bin/failsafe/su",
            "/system/bin/su",
            "/system/etc/init/magisk",
            "/system/etc/init/magisk.rc",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/system/xbin/bstk/su",
            "/system/xbin/daemonsu",
            "/system/xbin/mu_bak",
            "/system/xbin/su",
            "/system/xbin/sugote",
            "/system/xbin/sugote-mksh",
            "/system/xbin/supolicy",
            "/system_ext/bin/su",
            "/vendor/bin/su",
            "/vendor/xbin/su",
    };

}
