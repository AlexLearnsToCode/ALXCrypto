#
# Be sure to run `pod lib lint ALXCrypto.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'ALXCrypto'
  s.version          = '0.1.0'
  s.summary          = 'An easy crypto tool.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC

  s.homepage         = 'https://github.com/alexlearnstocode/ALXCrypto'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'alexlearnstocode' => '229570121@qq.com' }
  s.source           = { :git => 'https://github.com/alexlearnstocode/ALXCrypto.git', :tag => s.version.to_s }
  s.social_media_url = 'https://www.jianshu.com/u/fb6f45f5a7f6'

  s.ios.deployment_target = '8.0'

  s.source_files = 'ALXCrypto/Classes/**/*'
  
  # s.resource_bundles = {
  #   'ALXCrypto' => ['ALXCrypto/Assets/*.png']
  # }

#   s.public_header_files = 'ALXCrypto/Classes/**/*.h'
   s.frameworks = 'Foundation', 'Security'
  # s.dependency 'AFNetworking', '~> 2.3'
end
