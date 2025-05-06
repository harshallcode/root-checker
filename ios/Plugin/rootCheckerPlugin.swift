import Foundation
import Capacitor

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(RootCheckerPlugin)
public class RootCheckerPlugin: CAPPlugin {
    private let implementation = RootChecker()

    @objc func checkRoot(_call: CAPPluginCall) {
        call.resolve([
            "isRooted": false
        ])
    }
}
