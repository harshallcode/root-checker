import Foundation
import Capacitor

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(rootCheckerPlugin)
public class rootCheckerPlugin: CAPPlugin {
    private let implementation = rootChecker()

    @objc func checkRoot(_call: CAPPluginCall) {
        call.resolve([
            "isRooted": false
        ])
    }
}
