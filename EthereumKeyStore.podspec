Pod::Spec.new do |s|
s.name             = 'EthereumKeyStore'
s.version          = '0.1.0'
s.summary          = 'Wow EthereumKeyStore.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

# 长的描述信息
s.description      = <<-DESC
Wow this is a amazing kit,
Enjoy yourself!
DESC

# 提交到git服务区的项目主页，没提交可以指定任意值，但需要保留这一项，否则会报错
# attributes: Missing required attribute `homepage`.
s.homepage         = 'https://github.com/DuGuXiaoXia/EthereumKeyStore'
# s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
# 授权文件
s.license          = { :type => 'MIT', :file => 'LICENSE' }
# 用户信息
s.author           = { 'DuGuXiaoXia' => 'guojian1947@163.com' }
# 提交到git上的源码路径，没提交可以指定任意值，但需要保留这一项，否则会报错
# attributes: Missing required attribute `source`.
s.source       = { :git => "https://github.com/DuGuXiaoXia/EthereumKeyStore.git",:tag => s.version, :commit => "63de47e31391048c97794fd2ec98d3431d5cc0e1" }
# s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

#s.platform     = :swift, "3.2"
# 指定最低的ios版本
s.ios.deployment_target = '8.0'

# 源文件的路径
s.source_files = 'EthereumKeyStore/*'

# 公共的头文件，按需设置
#s.public_header_files = 'EthereumKeyStore/Classes/Public/**/*.h'
# 私有的头文件，按需设置
#s.private_header_files = 'EthereumKeyStore/Classes/Private/**/*.h'
# 依赖的系统Framework，按需设置
# s.frameworks = 'UIKit', 'MapKit'
# 依赖其他的pod库，按需设置
# s.dependency 'AFNetworking', '~> 2.3'
end
