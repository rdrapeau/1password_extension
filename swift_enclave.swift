import Foundation
import LocalAuthentication

// swift_enclave prompt <reason>
// Presents a Touch ID / passcode dialog. Outputs:
//   AUTH_SUCCESS   — user authenticated
//   AUTH_CANCELLED — user cancelled or biometrics unavailable

if CommandLine.arguments.count < 3 {
    print("Usage: swift_enclave prompt <reason>")
    exit(1)
}

let action = CommandLine.arguments[1]
guard action == "prompt" else {
    print("Unknown action: \(action). Expected: prompt")
    exit(1)
}

let reason = CommandLine.arguments[2]
let context = LAContext()
var authError: NSError?

let policy: LAPolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError)
    ? .deviceOwnerAuthenticationWithBiometrics
    : .deviceOwnerAuthentication

guard context.canEvaluatePolicy(policy, error: &authError) else {
    print("AUTH_CANCELLED")
    exit(0)
}

let sema = DispatchSemaphore(value: 0)
var authSuccess = false

context.evaluatePolicy(policy, localizedReason: reason) { success, _ in
    authSuccess = success
    sema.signal()
}

sema.wait()
print(authSuccess ? "AUTH_SUCCESS" : "AUTH_CANCELLED")
exit(0)
