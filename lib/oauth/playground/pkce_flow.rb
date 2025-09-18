# frozen_string_literal: true

require "oauth2"
require "securerandom"
require "base64"
require "digest"
require "uri"
require "jwt"
require "net/http"
require "json"
require "logger"

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
      attr_reader :logger

      def initialize(options = {})
        @logger = options[:logger] || Logger.new($stdout, level: Logger::INFO)
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
        logger.info "Starting OAuth2 PKCE Flow..."
        logger.info "=" * 50

        display_config

        logger.info "\nStep 1: Generate PKCE parameters"
        logger.info "Code Verifier: #{@code_verifier}"
        logger.info "Code Challenge: #{@code_challenge}"
        logger.info "Code Challenge Method: S256"

        logger.info "\nStep 2: Build Authorization URL"
        auth_url = build_authorization_url
        logger.info "Authorization URL:"
        logger.info auth_url

        logger.info "\nStep 3: Open the URL in your browser and complete the authorization"
        logger.info "After authorization, you'll be redirected with an authorization code"
        logger.info "\nStep 4: Enter the authorization code to exchange for tokens"
        print "Authorization code: "

        auth_code = gets.chomp

        if auth_code.empty?
          logger.warn "No authorization code provided. Exiting."
          return
        end

        logger.info "\nStep 5: Exchange authorization code for tokens"
        exchange_code_for_tokens(auth_code)
      rescue StandardError => e
        logger.error "Error: #{e.message}"
        logger.debug e.backtrace if ENV["DEBUG"]
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
        logger.info "Configuration:"
        logger.info "  Client ID: #{@client_id}"
        logger.info "  Scope: #{@scope}"
        logger.info "  Redirect URI: #{@redirect_uri}"
        logger.info "  Nonce: #{@nonce}" if @nonce
        logger.info "  State: #{@state}" if @state
        logger.info "  Auth URL: #{@auth_url}"
        logger.info "  Token URL: #{@token_url}"
        logger.info "  JWKS URI: #{@jwks_uri}" if @jwks_uri
        logger.info "  UserInfo URL: #{@userinfo_url}" if @userinfo_url
        logger.info "  Expected Issuer: #{@issuer}" if @issuer
        logger.info "  Expected Audience: #{@audience}" if @audience
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

        logger.info "Requesting tokens with parameters:"
        token_params.each { |k, v| logger.info "  #{k}: #{v}" }

        token = client.auth_code.get_token(auth_code, token_params)

        logger.info "\nTokens received successfully!"
        logger.info "Access Token: #{token.token}"
        logger.info "Refresh Token: #{token.refresh_token}" if token.refresh_token
        logger.info "Token Type: #{token.params["token_type"]}"
        logger.info "Expires In: #{token.params["expires_in"]} seconds" if token.params["expires_in"]
        logger.info "ID Token: #{token.params["id_token"]}" if token.params["id_token"]

        if token.params["id_token"] && @jwks_uri
          logger.info "\nStep 6: Validate ID Token"
          validate_id_token(token.params["id_token"], token.token)
        end
      rescue OAuth2::Error => e
        logger.error "OAuth2 Error: #{e.message}"
        logger.error "Response: #{e.response.body}" if e.response
      end

      def validate_id_token(id_token, access_token)
        logger.info "Fetching JWKS from: #{@jwks_uri}"
        jwks = fetch_jwks(@jwks_uri)

        logger.info "Decoding and validating ID token..."
        jwt_options = {
          algorithm: "RS256",
          jwks: jwks,
          verify_iss: @issuer ? true : false,
          verify_aud: @audience ? true : false
        }

        jwt_options[:iss] = @issuer if @issuer
        jwt_options[:aud] = @audience if @audience

        logger.debug "JWT validation options: #{jwt_options.inspect}"

        decoded_token, = JWT.decode(
          id_token,
          nil,
          true,
          jwt_options
        )

        payload = decoded_token
        logger.info "ID Token validation successful!"
        logger.info "Token claims:"
        payload.each { |k, v| logger.info "  #{k}: #{v}" }

        if @nonce && payload["nonce"] != @nonce
          logger.warn "⚠️  WARNING: Nonce mismatch! Expected: #{@nonce}, Got: #{payload["nonce"]}"
        else
          logger.info "✅ Nonce validation passed"
        end

        if @userinfo_url
          logger.info "\\nStep 7: Validate against UserInfo endpoint"
          validate_userinfo(access_token, payload)
        end
      rescue JWT::DecodeError => e
        logger.error "❌ ID Token validation failed: #{e.message}"
      rescue StandardError => e
        logger.error "❌ Error validating ID token: #{e.message}"
      end

      def fetch_jwks(jwks_uri)
        uri = URI(jwks_uri)
        response = Net::HTTP.get_response(uri)

        raise "Failed to fetch JWKS: HTTP #{response.code}" unless response.code == "200"

        jwks_data = JSON.parse(response.body)
        logger.debug "Fetched #{jwks_data}  from JWKS"

        jwks_data
      end

      def validate_userinfo(access_token, id_token_payload)
        logger.info "Fetching UserInfo from: #{@userinfo_url}"

        uri = URI(@userinfo_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"

        request = Net::HTTP::Get.new(uri)
        request["Authorization"] = "Bearer #{access_token}"

        response = http.request(request)

        unless response.code == "200"
          logger.error "❌ UserInfo request failed: HTTP #{response.code}"
          return
        end

        userinfo = JSON.parse(response.body)
        logger.info "UserInfo retrieved successfully!"
        logger.info "UserInfo claims:"
        userinfo.each { |k, v| logger.info "  #{k}: #{v}" }

        logger.info "Validating ID token against UserInfo..."
        validate_claims_consistency(id_token_payload, userinfo)
      rescue StandardError => e
        logger.error "❌ Error validating UserInfo: #{e.message}"
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
          logger.info "✅ All common claims are consistent between ID token and UserInfo"
        else
          logger.warn "⚠️  WARNING: Inconsistencies found:"
          inconsistencies.each { |inconsistency| logger.warn "  #{inconsistency}" }
        end
      end

      def extract_base_url(url)
        uri = URI(url)
        "#{uri.scheme}://#{uri.host}#{":#{uri.port}" unless [80, 443].include?(uri.port)}"
      end
    end
  end
end
