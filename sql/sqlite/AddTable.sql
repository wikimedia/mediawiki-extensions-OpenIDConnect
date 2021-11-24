CREATE TABLE /*_*/openid_connect (
  oidc_user int unsigned PRIMARY KEY NOT NULL,
  oidc_subject TINYBLOB NOT NULL,
  oidc_issuer TINYBLOB NOT NULL
) /*$wgDBTableOptions*/;
CREATE INDEX /*i*/openid_connect_subject ON /*_*/openid_connect (oidc_subject(50),oidc_issuer(50));
