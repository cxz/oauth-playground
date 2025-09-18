# frozen_string_literal: true

require_relative "playground/version"
require_relative "playground/pkce_flow"

module Oauth
  module Playground
    class Error < StandardError; end
  end
end
