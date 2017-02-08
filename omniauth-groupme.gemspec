# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-groupme/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-groupme"
  spec.version       = Omniauth::Groupme::VERSION
  spec.authors       = ["Brandon Hilkert"]
  spec.email         = ["brandonhilkert@gmail.com"]

  spec.summary       = %q{OmniAuth strategy for GroupMe}
  spec.description   = %q{OmniAuth strategy for GroupMe}
  spec.homepage      = "https://github.com/Bark-us/omniauth-groupme"
  spec.license        = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'omniauth-oauth2'
  spec.add_runtime_dependency 'multi_json'

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
