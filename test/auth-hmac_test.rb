require File.expand_path(File.join(File.dirname(__FILE__), 'helper'))
# require 'rack/utils'

class AuthHMACMiddlewareTest < Faraday::TestCase
  def setup
    Faraday::Request::AuthHMAC.keys.clear
    @access_id, @secret = "app_id", "secret"
    @connection = Faraday.new do |c|
      c.request :auth_hmac
      c.adapter :test do |stub|
        stub.get('/api') do |env|
          [200, nil, env[:body]]
        end
      end
    end
  end

  def test_auth_hmac_skips_when_sign_is_not_called
    response = @connection.get 'http://sushi.com/api'
    assert_nil response.env[:request_headers]['Authorization']
  end

  def test_request_will_instruct_middleware_to_sign_if_told_to
    response = @connection.get 'http://sushi.com/api' do |r|
      r.sign! @access_id, @secret
    end
    assert_match /#{@access_id}/, response.env[:request_headers]['Authorization']
  end

  def test_request_instructed_to_sign_a_request_will_result_in_a_correctly_signed_request
    response = @connection.get 'http://sushi.com/api' do |resp|
      resp.sign! @access_id, @secret
    end
    assert signed?(response.env, @access_id, @secret), "should be signed"
  end

  def test_a_signed_request_includes_appropriate_headers
    response = @connection.get 'http://sushi.com/api' do |resp|
      resp.sign! @access_id, @secret
      resp.body = 'test'
    end
    %w(Authorization Content-MD5 Date).each do |header|
      assert_not_nil response.env[:request_headers][header], "should have #{header} header"
    end
  end

  protected

  def klass
    Faraday::Request::AuthHMAC
  end

  # Based on the `authenticated?` method in auth-hmac.
  # https://github.com/dnclabs/auth-hmac/blob/master/lib/auth-hmac.rb#L252
  def signed?(env, access_id, secret)
    auth  = klass.auth
    rx = Regexp.new("#{klass.options[:service_id]} ([^:]+):(.+)$")
    if md = rx.match(env[:request_headers][klass::AUTH_HEADER])
      access_key_id = md[1]
      hmac = md[2]
      !secret.nil? && hmac == auth.signature(env, secret)
    else
      false
    end
  end

end
