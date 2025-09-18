#!/bin/bash

bin/pkce \
  --client-id "b859d33d1834b771dd19a87e2d419579d11dbbe8697bb3a7691b7191be44c2b5bb2d2dabb26e483cea515f00d55ff821781c7ab91f714e5e674332bfcec91878" \
  --scope "openid email profile" \
  --redirect-uri "https://services.yonomi.cloud/login/callback" \
  --nonce "9hqPS6oGnCTlRtzYGU390i3xQXOJIiB2O0o-BZfiORk" \
  --state "B87SxxVcnTOAJGqlezRdQmnrLWavjM0f" \
  --auth-url "https://backend.rl.ama1a.org/oauth/authorize" \
  --token-url "https://backend.rl.ama1a.org/oauth/token" \
  --jwks-uri "https://backend.rl.ama1a.org/oauth/discovery/keys" \
  --userinfo-url "https://backend.rl.ama1a.org/oauth/userinfo"
