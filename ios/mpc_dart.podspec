Pod::Spec.new do |s|
  s.name             = 'mpc_dart'
  s.version          = '1.0.0'
  s.summary          = 'Threshold signature (MPC) FFI plugin for Flutter.'
  s.description      = 'Flutter FFI bindings for {2,n}-threshold ECDSA and Ed25519, powered by a Go core (okx/threshold-lib).'
  s.homepage         = 'https://github.com/hyper-fi/mpc-dart'
  s.license          = { :type => 'Apache-2.0', :file => '../LICENSE' }
  s.author           = { 'hyper-fi' => 'dev@hyper.fi' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  # Static Go archives (device + simulator), force-loaded into the
  # mpc_dart.framework binary. FFI looks symbols up via RTLD_DEFAULT, nothing
  # references them at link time, so -force_load is required to keep them.
  s.preserve_paths   = '../native/ios/MpcDart.xcframework'
  go_frameworks = '-framework Foundation -framework CoreFoundation -framework Security -framework SystemConfiguration -framework CFNetwork'
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'OTHER_LDFLAGS[sdk=iphoneos*]' => "-Wl,-force_load,\"${PODS_TARGET_SRCROOT}/../native/ios/MpcDart.xcframework/ios-arm64/libmpc.a\" #{go_frameworks}",
    'OTHER_LDFLAGS[sdk=iphonesimulator*]' => "-Wl,-force_load,\"${PODS_TARGET_SRCROOT}/../native/ios/MpcDart.xcframework/ios-arm64-simulator/libmpc.a\" #{go_frameworks}"
  }
  s.dependency 'Flutter'
  s.platform         = :ios, '13.0'
  s.swift_version    = '5.0'
end
