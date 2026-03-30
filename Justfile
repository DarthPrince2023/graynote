
create_certificates:
    openssl genrsa -out ./ssl_certificates/graynote_key.pem 2048
    openssl req -new -key ./ssl_certificates/graynote_key.pem -out ./ssl_certificates/graynote.csr -subj "/\C=US/\ST=AZ/\L=Phoenix/\O=GrayNote/\OU=TestingKeyOnly/\CN=localhost"
    openssl x509 -req -in ./ssl_certificates/graynote.csr -signkey ./ssl_certificates/graynote_key.pem -out ./ssl_certificates/graynote_cert.pem -days 365