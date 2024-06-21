There are some sensitive files to look at:
- Robots.txt;
- sitemap.xml;
- /.well-known/;

Well known registered URI:
- security.txt: Contains contact information for security researchers to report vulnerabilities;
- /.well-known/change-password: Provides a standard URL for directing users to a password change page;
- https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri;
- openid-configuration: Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol;	http://openid.net/specs/openid-connect-discovery-1_0.html
assetlinks.json	Used for verifying ownership of digital assets (e.g., apps) associated with a domain.	Permanent	https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md
mta-sts.txt	Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.	Permanent	RFC 8461