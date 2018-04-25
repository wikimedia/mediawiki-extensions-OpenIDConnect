CREATE TABLE openid_connect (
  oidc_user INTEGER NOT NULL PRIMARY KEY,
  oidc_subject VARCHAR(255) NOT NULL,
  oidc_issuer VARCHAR(255) NOT NULL
);
CREATE INDEX openid_connect_subject ON openid_connect (oidc_subject,oidc_issuer);
