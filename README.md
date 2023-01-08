# Code Signing .NET Code

First, you will need an Azure Key Vault.

Next, you will need to create a `codeSigning` certificate and upload it to AKV.

You can follow this document [Store the signing certificate in AKV](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-sign-build-push#store-the-signing-certificate-in-akv) (althought the original purpuse of the referenced document was for using notary, the storing cert in AKV part is the same.)

## **Create a self-signed certificate (Azure CLI)**

In a real world, we should be using an EV Code Signing Certificate, but for testing purpose, this is a good start.

```
# Name of the existing Azure Key Vault used to store the signing keys
AKV_NAME=<Azure Key Vault name>
# New desired key name used to sign and verify
KEY_NAME=<certificate name>
CERT_SUBJECT="<cert subject string>",
CERT_PATH=./${KEY_NAME}.pem
```

1. Create a certificate policy file.

```bash
cat <<EOF > ./my_policy.json
{
    "issuerParameters": {
    "certificateTransparency": null,
    "name": "Self"
    },
    "x509CertificateProperties": {
    "ekus": [
        "1.3.6.1.5.5.7.3.3"
    ],
    "keyUsage": [
        "digitalSignature"
    ],
    "subject": "$CERT_SUBJECT",
    "validityInMonths": 12
    }
}
EOF
```

2. Create a certificate

```bash
az keyvault certificate create -n $KEY_NAME --vault-name $AKV_NAME -p @my_policy.json
```

3. Download the public certificate

```bash
CERT_ID=$(az keyvault certificate show -n $KEY_NAME --vault-name $AKV_NAME --query 'id' -o tsv)
az keyvault certificate download --file $CERT_PATH --id $CERT_ID --encoding PEM
```

using this `.pem` file you can later verify the signatures, e.g.

```bash
osslsigncode verify -in HelloWorld.dll -CAfile signcode.pem
```

4. Download both private & public key using pfx format

```bash
az keyvault secret download --file ./${KEY_NAME}.pfx --vault-name $AKV_NAME --encoding base64 --name $KEY_NAME 2>&1
```

## **Create an Azure Principal for AKV access**

Our GitHub Actions will need a login to access AKV for code signing certificate.

[Use Key Vault secrets in GitHub Actions workflows](https://learn.microsoft.com/en-us/azure/developer/github/github-key-vault) .

```bash
# Name of the existing Azure Key Vault used to store the signing keys
AKV_NAME=csakv001
# New desired key name used to sign and verify
KEY_NAME=<cert name>
CERT_SUBJECT="<cert subject string>"
CERT_PATH=./${KEY_NAME}.pem
SUBSCRIPTION_ID=<az subscription id>
RESOURCE_GROUP=<az resouce group>
CLIENT_ID=<the Principal ID>
```

1. Create an `rbac` principal

```bash
az ad sp create-for-rbac --name AzureCodeSigning --role contributor --scopes /subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}
```

2. Grant permissions to AKV

```bash
az keyvault set-policy -n ${AKV_NAME} --secret-permissions get list --spn ${CLIENT_ID}
```

3. Save the Principal credentials to GitHub Actions as a repository secret: `secrets.AZURE_CREDENTIALS`

Some fields are repeated as I am not sure which fields are used by the GitHub Actions `Azure/login@v1`, the documentation has been lacking on this:

```
{
  "clientId": "<application id>",
  "clientSecret": "PSN password",
  "subscriptionId": "<azure subscription id>",
  "tenantId": "<Azure Directory ID>",
  "appId": "<same as the clientId>",
  "displayName": "PSN display name",
  "password": "<same as the clientSecret>",
  "tenant": "<same as the tenantId>"
}
```

# Summary

There is nothing to look at in the C# source code.

Whatever you may be interested should be in [the GitHub Actions workflow file](https://github.com/dliulabs/CodeSigning/blob/main/.github/workflows/ci.yaml).

If you download the release packages, you should find those HelloWorld.dll & HelloWorld.exe have been signed.

Here is an example of the signed HelloWorld.dll from the release package.

```text
$ osslsigncode verify -in HelloWorld-v1.0.0-linux-x64/HelloWorld.dll -CAfile ./signcode.pem

Current PE checksum   : 0000A1C4
Calculated PE checksum: 0000A1C4

Signature Index: 0  (Primary Signature)
Message digest algorithm  : SHA256
Current message digest    : B243F587D4783A7E029B3F3BDD4F3726D0860B7D9B91145EC43D549C146F78D2
Calculated message digest : B243F587D4783A7E029B3F3BDD4F3726D0860B7D9B91145EC43D549C146F78D2

Signer's certificate:
	Signer #0:
		Subject: /C=US/ST=TN/L=Nashville/O=Notary/CN=codesigning.gtp.ey.com
		Issuer : /C=US/ST=TN/L=Nashville/O=Notary/CN=codesigning.gtp.ey.com
		Serial : 7C0EE51445C54A78862A77878F272BB9
		Certificate expiration date:
			notBefore : Jan  7 22:06:38 2023 GMT
			notAfter : Jan  7 22:16:38 2024 GMT

Number of certificates: 4
	Signer #0:
		Subject: /C=US/ST=TN/L=Nashville/O=Notary/CN=codesigning.gtp.ey.com
		Issuer : /C=US/ST=TN/L=Nashville/O=Notary/CN=codesigning.gtp.ey.com
		Serial : 7C0EE51445C54A78862A77878F272BB9
		Certificate expiration date:
			notBefore : Jan  7 22:06:38 2023 GMT
			notAfter : Jan  7 22:16:38 2024 GMT
	------------------
	Signer #1:
		Subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Assured ID Root CA
		Serial : 0E9B188EF9D02DE7EFDB50E20840185A
		Certificate expiration date:
			notBefore : Aug  1 00:00:00 2022 GMT
			notAfter : Nov  9 23:59:59 2031 GMT
	------------------
	Signer #2:
		Subject: /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA
		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
		Serial : 073637B724547CD847ACFD28662A5E5B
		Certificate expiration date:
			notBefore : Mar 23 00:00:00 2022 GMT
			notAfter : Mar 22 23:59:59 2037 GMT
	------------------
	Signer #3:
		Subject: /C=US/O=DigiCert/CN=DigiCert Timestamp 2022 - 2
		Issuer : /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA
		Serial : 0C4D69724B94FA3C2A4A3D2907803D5A
		Certificate expiration date:
			notBefore : Sep 21 00:00:00 2022 GMT
			notAfter : Nov 21 23:59:59 2033 GMT

Authenticated attributes:
	Message digest algorithm: SHA256
	Message digest: 2622976E1CF9634A7E62A0E514DB63C995F760184176A69F5DC94682DF5D57C6
	Signing time: Jan  9 02:23:43 2023 GMT
	Microsoft Individual Code Signing purpose
	Text description: codesigning-gtp-ey

The signature is timestamped: Jan  9 02:23:43 2023 GMT
Hash Algorithm: sha256
Timestamp Verified by:
		Issuer : /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA
		Serial : 0C4D69724B94FA3C2A4A3D2907803D5A

CAfile: ./signcode.pem
TSA's certificates file: /etc/ssl/cert.pem
TSA's CRL distribution point: http://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl


Timestamp Server Signature verification: ok
Signature verification: ok

Number of verified signatures: 1
Succeeded
```
