# frozen_string_literal: true

require 'kafka/sasl/plain'
require 'kafka/sasl/gssapi'
require 'kafka/sasl/scram'
require 'kafka/sasl/oauth_bearer'

module Kafka
  class SaslAuthenticator
    def initialize(logger:, sasl_gssapi_principal:, sasl_gssapi_keytab:,
                   sasl_plain_authzid:, sasl_plain_username:, sasl_plain_password:,
                   sasl_scram_username:, sasl_scram_password:, sasl_scram_mechanism:,
                   sasl_oauth_client_id:, sasl_oauth_client_secret:, sasl_oauth_server_url:, sasl_oauth_token_url:)
      @logger = logger

      @plain = Sasl::Plain.new(
        authzid: sasl_plain_authzid,
        username: sasl_plain_username,
        password: sasl_plain_password,
        logger: @logger,
      )

      @gssapi = Sasl::Gssapi.new(
        principal: sasl_gssapi_principal,
        keytab: sasl_gssapi_keytab,
        logger: @logger,
      )

      @scram = Sasl::Scram.new(
        username: sasl_scram_username,
        password: sasl_scram_password,
        mechanism: sasl_scram_mechanism,
        logger: @logger,
      )

      @oauth = Sasl::OAuthBearer.new(
        logger: @logger,
        client_id: sasl_oauth_client_id,
        client_secret: sasl_oauth_client_secret,
        server_url: sasl_oauth_server_url,
        token_url: sasl_oauth_token_url
      )

      @mechanism = [@gssapi, @plain, @scram, @oauth].find(&:configured?)
    end

    def enabled?
      !@mechanism.nil?
    end

    def authenticate!(connection)
      return unless enabled?

      ident = @mechanism.ident
      response = connection.send_request(Kafka::Protocol::SaslHandshakeRequest.new(ident))

      unless response.error_code == 0 && response.enabled_mechanisms.include?(ident)
        raise Kafka::Error, "#{ident} is not supported."
      end

      @mechanism.authenticate!(connection.to_s, connection.encoder, connection.decoder)
    end
  end
end
