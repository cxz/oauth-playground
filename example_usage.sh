#!/bin/bash

bin/pkce \
  --client-id "" \
  --scope "openid email profile" \
  --redirect-uri "https://aaa/login/callback" \
  --nonce "9hqPS6oGnCTlRtzYGU390i3xQXOJIiB2O0o-BZfiORk" \
  --state "B87SxxVcnTOAJGqlezRdQmnrLWavjM0f" \
  --auth-url "https://bbb/oauth/authorize" \
  --token-url "https://bbb/oauth/token" \
  --jwks-uri "https://bbb/oauth/discovery/keys" \
  --userinfo-url "https://bbb/oauth/userinfo" \
  --issuer "https://bbb" \
  --audience "your-client-id"
