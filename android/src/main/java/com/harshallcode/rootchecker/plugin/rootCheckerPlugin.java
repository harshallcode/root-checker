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
    public void checkRoot(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("isRooted",new RootBeer(getContext()).isRooted());
        call.resolve(ret);
    }
}
