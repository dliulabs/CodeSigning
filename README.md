# Code Sign .NET Code

First, you will need an Azure Key Vault.

Next, you will need to create a `codeSigning` certificate and upload it to AKV.

You can follow this document [Store the signing certificate in AKV](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-sign-build-push#store-the-signing-certificate-in-akv) (althought the original purpuse of the referenced document was for using notary, the storing cert in AKV part is the same.)

## **Create a self-signed certificate (Azure CLI)**

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
