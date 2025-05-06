import Foundation

@objc public class RootChecker: NSObject {
    @objc public func echo(_ value: String) -> String {
        print(value)
        return value
    }
}
