require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Groupme < OmniAuth::Strategies::OAuth2
      option :name, "groupme"
      option :client_options, { site: "https://oauth.groupme.com" }
      option :provider_ignores_state, true
      option :auth_token_params, { mode: :query, param_name: :token }

      uid { raw_info['id'] }

      info do
        {
          name: raw_info["name"],
          email: raw_info["email"],
          image: raw_info["image_url"],
          phone: raw_info["phone_number"],
          sms: raw_info["sms"],
        }
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      def request_phase
        redirect client.implicit.authorize_url({ redirect_uri: callback_url })
      end

      def raw_info
        @raw_info ||= access_token.get('https://api.groupme.com/v3/users/me').parsed["response"]
      end

      def callback_phase
        error = request.params["error_reason"] || request.params["error"]
        if error
          fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
        elsif !options.provider_ignores_state && (request.params["state"].to_s.empty? || request.params["state"] != session.delete("omniauth.state"))
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
        else
          self.access_token = build_access_token(request.params["access_token"])
          env['omniauth.auth'] = auth_hash
          call_app!
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def build_access_token(access_token)
        ::OAuth2::AccessToken.new(client, access_token, options.auth_token_params)
      end
    end
  end
end
