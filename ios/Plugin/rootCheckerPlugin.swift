import Foundation
import Capacitor

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(rootCheckerPlugin)
public class rootCheckerPlugin: CAPPlugin {
    private let implementation = rootChecker()

    @objc func echo(_ call: CAPPluginCall) {
        let value = call.getString("value") ?? ""
        call.resolve([
            "value": implementation.echo(value)
        ])
    }
    @objc func checkRoot() {
        try {
            java.util.Scanner s = new java.util.Scanner(
                Runtime.getRuntime().exec(new String[] { "/system/bin/su", "-c", "cd / && ls" }).getInputStream()
            )
                .useDelimiter("\\A");
            call.resolve(!(s.hasNext() ? s.next() : "").equals(""));
        } catch (IOException e) {
            e.printStackTrace();
            
        }
        // return false;
        call.resolve(false)
    }
}
