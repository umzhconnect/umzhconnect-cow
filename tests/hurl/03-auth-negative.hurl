# =============================================================================
# 03-auth-negative — the external gateway rejects unauthenticated / bad-token
# requests before any policy or upstream is consulted (openid-connect,
# bearer_only). No valid token needed to run this file.
# =============================================================================

# No Authorization header -> 401.
GET {{gateway_url}}/fhir/Task
HTTP 401

GET {{gateway_url}}/fhir/ServiceRequest?_id=anything
HTTP 401

# Malformed bearer -> 401.
GET {{gateway_url}}/fhir/Task
Authorization: Bearer not-a-jwt
HTTP 401

# Well-formed but unsigned/tampered JWT -> 401.
GET {{gateway_url}}/fhir/Task
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwiZXhwIjoxMH0.bad
HTTP 401
