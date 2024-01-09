package com.harshallcode.rootchecker.plugin;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "rootChecker")
public class rootCheckerPlugin extends Plugin {

    private rootChecker implementation = new rootChecker();

    @PluginMethod()
    public void echo(PluginCall call) {
        String value = call.getString("value");

        JSObject ret = new JSObject();
        ret.put("value", implementation.echo(value));
        call.resolve(ret);
    }

    @PluginMethod()
    public boolean checkRoot() {
        if (new RootBeer(this).isRooted()) {
            call.getBoolean("isRooted",true)
        } else {
            call.getBoolean("isRooted",false)
        }
        // try {
        //     java.util.Scanner s = new java.util.Scanner(
        //         Runtime.getRuntime().exec(new String[] { "/system/bin/su", "-c", "cd / && ls" }).getInputStream()
        //     )
        //         .useDelimiter("\\A");
        //     call.getBoolean("isRooted",!(s.hasNext() ? s.next() : "").equals(""));
        // } catch (IOException e) {
        //     e.printStackTrace();

        // }
        // call.getBoolean("isRooted",false)
        // call.resolve()
    }

    
}
