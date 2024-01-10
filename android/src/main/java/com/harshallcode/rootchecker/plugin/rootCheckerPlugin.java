package com.harshallcode.rootchecker.plugin;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.scottyab.rootbeer.RootBeer;

@CapacitorPlugin(name = "rootChecker")
public class rootCheckerPlugin extends Plugin {

    private final rootChecker implementation = new rootChecker();

    @PluginMethod()
    public void echo(PluginCall call) {
        String value = call.getString("value");

        JSObject ret = new JSObject();
        ret.put("value", implementation.echo(value));
        call.resolve(ret);
    }

    @PluginMethod()
    public void checkRoot(PluginCall call) {
        call.getBoolean("isRooted", new RootBeer(getContext()).isRooted());
        call.resolve();
    }

    
}
