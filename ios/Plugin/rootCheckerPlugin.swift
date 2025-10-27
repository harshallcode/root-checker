import Foundation
import Capacitor
#import <DTTJailbreakDetection/DTTJailbreakDetection.h>

@objc(RootCheckerPlugin)
public class RootCheckerPlugin: CAPPlugin {
    private let implementation = RootChecker()

    @objc func checkRoot(_ call: CAPPluginCall) {
        if ([DTTJailbreakDetection isJailbroken]) {
            call.resolve([
                "isRooted": true
            ])
        } else {
            call.resolve([
                "isRooted": false
            ])
        }
    }
}
