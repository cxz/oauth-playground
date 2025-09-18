# frozen_string_literal: true

require "oauth2"
require "securerandom"
require "base64"
require "digest"
require "uri"
require "jwt"
require "net/http"
require "json"

module Oauth
  module Playground
    #   Key concepts refresher
    #
    #   - OAuth 2.0 delegates authorization; it does not define authentication of the end-user.
    #   - OIDC layers an identity layer on top of OAuth 2.0, introducing:
    #     - ID Token: a JWT carrying claims about the authenticated end-user and the authentication event.
    #     - Standardized scopes: openid (mandatory), profile, email, address, phone, offline_access, and others.
    #     - UserInfo endpoint: a protected resource for retrieving user profile claims.
    #      - Discovery and Dynamic Client Registration (optional for providers/clients that support them).
    #
    class PkceFlow
      def initialize(options = {})
        @client_id = options[:client_id]
        @scope = options[:scope] || "openid email profile"
        @redirect_uri = options[:redirect_uri]
        @nonce = options[:nonce]
        @state = options[:state]
        @auth_url = options[:auth_url]
        @token_url = options[:token_url]
        @jwks_uri = options[:jwks_uri]
        @userinfo_url = options[:userinfo_url]
        @issuer = options[:issuer]
        @audience = options[:audience] || options[:client_id]

        validate_required_options!
        generate_pkce_params
      end

      def start
        puts "Starting OAuth2 PKCE Flow..."
        puts "=" * 50

        display_config

        puts "\nStep 1: Generate PKCE parameters"
        puts "Code Verifier: #{@code_verifier}"
        puts "Code Challenge: #{@code_challenge}"
        puts "Code Challenge Method: S256"

        puts "\nStep 2: Build Authorization URL"
        auth_url = build_authorization_url
        puts "Authorization URL:"
        puts auth_url

        puts "\nStep 3: Open the URL in your browser and complete the authorization"
        puts "After authorization, you'll be redirected with an authorization code"
        puts "\nStep 4: Enter the authorization code to exchange for tokens"
        print "Authorization code: "

        auth_code = gets.chomp

        if auth_code.empty?
          puts "No authorization code provided. Exiting."
          return
        end

        puts "\nStep 5: Exchange authorization code for tokens"
        exchange_code_for_tokens(auth_code)
      rescue StandardError => e
        puts "Error: #{e.message}"
        puts e.backtrace if ENV["DEBUG"]
      end

      private

      def validate_required_options!
        required = %i[client_id redirect_uri auth_url token_url]
        missing = required.select { |key| instance_variable_get(:"@#{key}").nil? }

        return unless missing.any?

        raise ArgumentError, "Missing required options: #{missing.join(", ")}"
      end

      def generate_pkce_params
        @code_verifier = Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false)
        @code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(@code_verifier), padding: false)
      end

      def display_config
        puts "Configuration:"
        puts "  Client ID: #{@client_id}"
        puts "  Scope: #{@scope}"
        puts "  Redirect URI: #{@redirect_uri}"
        puts "  Nonce: #{@nonce}" if @nonce
        puts "  State: #{@state}" if @state
        puts "  Auth URL: #{@auth_url}"
        puts "  Token URL: #{@token_url}"
        puts "  JWKS URI: #{@jwks_uri}" if @jwks_uri
        puts "  UserInfo URL: #{@userinfo_url}" if @userinfo_url
        puts "  Expected Issuer: #{@issuer}" if @issuer
        puts "  Expected Audience: #{@audience}" if @audience
      end

      def build_authorization_url
        params = {
          client_id: @client_id,
          scope: @scope,
          response_type: "code",
          redirect_uri: @redirect_uri,
          code_challenge: @code_challenge,
          code_challenge_method: "S256"
        }

        params[:nonce] = @nonce if @nonce
        params[:state] = @state if @state

        uri = URI(@auth_url)
        uri.query = URI.encode_www_form(params)
        uri.to_s
      end

      def exchange_code_for_tokens(auth_code)
        client = OAuth2::Client.new(
          @client_id,
          nil,
          site: extract_base_url(@auth_url),
          token_url: @token_url
        )

        token_params = {
          grant_type: "authorization_code",
          code: auth_code,
          redirect_uri: @redirect_uri,
          code_verifier: @code_verifier,
          client_id: @client_id
        }

        puts "Requesting tokens with parameters:"
        token_params.each { |k, v| puts "  #{k}: #{v}" }

        token = client.auth_code.get_token(auth_code, token_params)

        puts "\nTokens received successfully!"
        puts "Access Token: #{token.token}"
        puts "Refresh Token: #{token.refresh_token}" if token.refresh_token
        puts "Token Type: #{token.params["token_type"]}"
        puts "Expires In: #{token.params["expires_in"]} seconds" if token.params["expires_in"]
        puts "ID Token: #{token.params["id_token"]}" if token.params["id_token"]

        if token.params["id_token"] && @jwks_uri
          puts "\nStep 6: Validate ID Token"
          validate_id_token(token.params["id_token"], token.token)
        end
      rescue OAuth2::Error => e
        puts "OAuth2 Error: #{e.message}"
        puts "Response: #{e.response.body}" if e.response
      end

      def validate_id_token(id_token, access_token)
        puts "Fetching JWKS from: #{@jwks_uri}"
        jwks = fetch_jwks(@jwks_uri)

        puts "Decoding and validating ID token..."
        jwt_options = {
          algorithm: "RS256",
          jwks: jwks,
          verify_iss: @issuer ? true : false,
          verify_aud: @audience ? true : false
        }

        jwt_options[:iss] = @issuer if @issuer
        jwt_options[:aud] = @audience if @audience

        puts "JWT validation options: #{jwt_options.inspect}"

        decoded_token, = JWT.decode(
          id_token,
          nil,
          true,
          jwt_options
        )

        payload = decoded_token
        puts "ID Token validation successful!"
        puts "Token claims:"
        payload.each { |k, v| puts "  #{k}: #{v}" }

        if @nonce && payload["nonce"] != @nonce
          puts "⚠️  WARNING: Nonce mismatch! Expected: #{@nonce}, Got: #{payload["nonce"]}"
        else
          puts "✅ Nonce validation passed"
        end

        if @userinfo_url
          puts "\\nStep 7: Validate against UserInfo endpoint"
          validate_userinfo(access_token, payload)
        end
      rescue JWT::DecodeError => e
        puts "❌ ID Token validation failed: #{e.message}"
      rescue StandardError => e
        puts "❌ Error validating ID token: #{e.message}"
      end

      def fetch_jwks(jwks_uri)
        uri = URI(jwks_uri)
        response = Net::HTTP.get_response(uri)

        raise "Failed to fetch JWKS: HTTP #{response.code}" unless response.code == "200"

        jwks_data = JSON.parse(response.body)
        puts "Fetched #{jwks_data}  from JWKS"

        jwks_data
      end

      def validate_userinfo(access_token, id_token_payload)
        puts "Fetching UserInfo from: #{@userinfo_url}"

        uri = URI(@userinfo_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"

        request = Net::HTTP::Get.new(uri)
        request["Authorization"] = "Bearer #{access_token}"

        response = http.request(request)

        unless response.code == "200"
          puts "❌ UserInfo request failed: HTTP #{response.code}"
          return
        end

        userinfo = JSON.parse(response.body)
        puts "UserInfo retrieved successfully!"
        puts "UserInfo claims:"
        userinfo.each { |k, v| puts "  #{k}: #{v}" }

        puts "Validating ID token against UserInfo..."
        validate_claims_consistency(id_token_payload, userinfo)
      rescue StandardError => e
        puts "❌ Error validating UserInfo: #{e.message}"
      end

      def validate_claims_consistency(id_token_payload, userinfo)
        common_claims = %w[sub email name given_name family_name]
        inconsistencies = []

        common_claims.each do |claim|
          id_value = id_token_payload[claim]
          userinfo_value = userinfo[claim]

          if id_value && userinfo_value && id_value != userinfo_value
            inconsistencies << "#{claim}: ID token has '#{id_value}', UserInfo has '#{userinfo_value}'"
          end
        end

        if inconsistencies.empty?
          puts "✅ All common claims are consistent between ID token and UserInfo"
        else
          puts "⚠️  WARNING: Inconsistencies found:"
          inconsistencies.each { |inconsistency| puts "  #{inconsistency}" }
        end
      end

      def extract_base_url(url)
        uri = URI(url)
        "#{uri.scheme}://#{uri.host}#{":#{uri.port}" unless [80, 443].include?(uri.port)}"
      end
    end
  end
end
