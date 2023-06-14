# derived from: https://github.com/zhuowei/CoreTrustDemo/blob/main/badcert/makecerts.sh

mkdir certs

openssl req -newkey rsa:2048 -nodes -keyout certs/root_key.pem -x509 -days 3650 -out certs/root_certificate.pem \
	-subj "/C=CA/O=Linden/OU=Linden Certification Authority/CN=Linden Root CA" \
	-addext "1.2.840.113635.100.6.22=DER:0500" \
	-addext "basicConstraints=critical, CA:true" -addext "keyUsage=critical, digitalSignature, keyCertSign, cRLSign"

openssl req -newkey rsa:2048 -nodes -keyout certs/codeca_key.pem -out certs/codeca_certificate.csr \
	-subj "/C=CA/O=Linden/OU=Linden Certification Authority/CN=Linden Developer ID Certification Authority" \
	-addext "1.2.840.113635.100.6.22=DER:0500" \
	-addext "basicConstraints=critical, CA:true" -addext "keyUsage=critical, keyCertSign, cRLSign"

openssl x509 -req -CAkey certs/root_key.pem -CA certs/root_certificate.pem -days 3650 \
	-in certs/codeca_certificate.csr -out certs/codeca_certificate.pem -CAcreateserial -copy_extensions copyall

openssl req -newkey rsa:2048 -nodes -keyout certs/dev_key.pem -out certs/dev_certificate.csr \
	-subj "/C=CA/O=Linden/OU=Linden Certification Authority/CN=Linden Developer ID" \
	-addext "basicConstraints=critical, CA:false" \
	-addext "keyUsage = critical, digitalSignature" -addext "extendedKeyUsage = codeSigning" \
	-addext "1.2.840.113635.100.6.22=DER:0500"

openssl x509 -req -CAkey certs/codeca_key.pem -CA certs/codeca_certificate.pem -days 3650 \
	-in certs/dev_certificate.csr -out certs/dev_certificate.pem -CAcreateserial -copy_extensions copyall

cat certs/codeca_certificate.pem certs/root_certificate.pem > certs/certificate_chain.pem
/usr/bin/openssl pkcs12 -export -in certs/dev_certificate.pem -inkey certs/dev_key.pem -certfile certs/certificate_chain.pem \
	-passout pass:linden \
	-out certs/dev_certificate.p12 -name "Linden Developer ID"
