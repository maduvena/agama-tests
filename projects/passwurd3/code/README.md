### Config parameters

```
{
    "AS_ENDPOINT": "https://account-dev.gluu.cloud",
    "AS_SSA": "ey...1BfBZQ0g",
    "AS_CLIENT_ID": "b71618...de21995120",
    "AS_CLIENT_SECRET": "52b9...9c505",
    "AS_REDIRECT_URI": "https://account-dev.gluu.cloud/.well-known/openid-configuration",
    "PORTAL_JWKS": "https://account-dev.gluu.cloud/jans-auth/restv1/jwks",
    "PASSWURD_KEY_A_KEYSTORE": "/etc/certs/passwurd_api.pkcs12",
    "PASSWURD_KEY_A_PASSWORD": "changeit",
    "PASSWURD_API_URL": "https://cloud-dev.gluu.cloud/scan/passwurd",
    "ORG_ID": "github:m...ena"
  }
```


### Pending features / bugs that are needed for this flow to work perfectly

1. Display appropriate error messages - https://github.com/GluuFederation/private/issues/3674

2. Org_id - issue - https://github.com/JanssenProject/jans/issues/5787

3. OTP flow, replace with real flow

4. Unable to add config to the project - https://github.com/GluuFederation/private/issues/3580


### Assumptions

1. Users already exist.
2. OTP for all users is 1234.
3. Wrong OTP will give error


### Cases in Passwurd API that dont work

1. During enrollment, each enrollment can have different values of password
2. Suppose the password for a user is user123, the API validates user123456 as well typed using the same pattern

