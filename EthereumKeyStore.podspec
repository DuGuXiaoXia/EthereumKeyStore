Pod::Spec.new do |s|
s.name         = 'EthereumKeyStore'
s.version      = '0.1.1'
s.summary      = 'A general-purpose Ethereum keystore for managing wallets.'
s.homepage     = 'https://github.com/DuGuXiaoXia/EthereumKeyStore'
s.license      = { :type => 'MIT', :file => 'LICENSE' }
s.authors      = { 'DuGuXiaoXia' => 'guojian1947@163.com' }

s.ios.deployment_target = '10.0'

s.source       = { git: 'https://github.com/DuGuXiaoXia/EthereumKeyStore.git', tag: s.version }
s.source_files = "EthereumKeyStore/**/*"

s.frameworks = 'Security'

s.dependency 'BigInt'
s.dependency 'CryptoSwift'
s.dependency 'TrezorCrypto'
s.dependency 'KeychainSwift'
s.dependency 'Result'
s.dependency 'SVProgressHUD'
s.dependency 'secp256k1_ios'


s.pod_target_xcconfig = { 'SWIFT_OPTIMIZATION_LEVEL' => '-Owholemodule' }
end
