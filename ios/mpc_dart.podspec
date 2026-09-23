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
  s.vendored_frameworks = '../native/ios/MpcDart.xcframework'
  s.dependency 'Flutter'
  s.platform         = :ios, '13.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version    = '5.0'
end
