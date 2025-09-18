# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development Setup
- `bin/setup` - Install dependencies and set up the development environment
- `bin/console` - Start an interactive Ruby console with the gem loaded

### Testing
- `rake spec` or `bundle exec rspec` - Run the full test suite
- `bundle exec rspec spec/path/to/spec.rb` - Run a specific test file
- `bundle exec rspec spec/path/to/spec.rb:line_number` - Run a specific test

### Code Quality
- `bundle exec rubocop` - Run RuboCop linting
- `bundle exec rubocop -a` - Auto-correct RuboCop violations where possible
- `rake` - Run both tests and linting (default task)

### Gem Management
- `bundle exec rake install` - Install the gem locally for testing
- `bundle exec rake release` - Release a new version (updates version, creates git tag, pushes to RubyGems)

## Architecture

This is a Ruby gem with a standard structure:

- **Main module**: `Oauth::Playground` in `lib/oauth/playground.rb` - Currently a minimal skeleton for OAuth flow experimentation
- **Version management**: `lib/oauth/playground/version.rb` - Contains the VERSION constant
- **Type signatures**: `sig/oauth/playground.rbs` - RBS type definitions for Ruby type checking
- **Test structure**: Uses RSpec with specs in `spec/` directory

### Code Style
- Uses double quotes for strings (enforced by RuboCop)
- Target Ruby version: 3.1+
- Follows standard Ruby gem conventions with `frozen_string_literal: true`

### Current State
This appears to be a newly created gem template for learning OAuth flows. The main module is largely empty with placeholder code that needs implementation.