# Local MC testing of APIs that trigger emails

See LocalTest.md first for basic setup info.

APIs to create a user trigger a verification email to be sent out. Also password reset requires the user to interact with their email.

In order to send email, MC must be started with VAULT_ROLE_ID and VAULT_SECRET_ID set to the MC's role and secret values, because the login information for the email account used to send emails is retrieved from Vault.

```
export VAULT_ROLE_ID=f4207f0f-c965-ac3e-181c-235de8838ff7
export VAULT_SECRET_ID=***REMOVED***
```

Start MC pointing to production Vault.

```
mc -localSql -d api -sqlAddr 127.0.0.1:5445 -vaultAddr https://vault.mobiledgex.net
```

## Welcome email (email verification)

Create a new user with a valid email account that you have access to.

```
http -j POST 127.0.0.1:9900/api/v1/usercreate name=me email=me@gmail.com passhash=test1234
```

Now check your email. You should have gotten a Welcome email like:

```
Hi me,

Thanks for creating a MobiledgeX account! You are now one step away from utilizing the power of the edge. Please verify this email account by clicking on the link below. Then you'll be able to login and get started.

Click to verify: http://console.mobiledgex.net/verify?token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTc0NjIyNDMsImlhdCI6MTU1NzM3NTg0MywidXNlcm5hbWUiOiJqb24iLCJlbWFpbCI6Impvbi5tb2JpbGVkZ2V4QGdtYWlsLmNvbSIsImtpZCI6M30.A5mcwkWlfjBUZ3Tvn0EqD_f0a4iPf7U-eg2aMASnrt7Lzdmp2CAEE5Q69g9HlTzE_oEpM3kOSeGhKYRKksvPTQ

For security, this request was received for me@gmail.com from a mac OSX device using httpie with IP 127.0.0.1. If you are not expecting this email, please ignore this email or contact MobiledgeX support for assistance.

Thanks!
MobiledgeX Team
```

This feature is not yet integreted into the UI, nor can the UI run locally against a local MC yet. So that link won't work. But, we can verify our email by directly calling the api. But first, let's try to log in.

```
http POST 127.0.0.1:9900/api/v1/login username=me password=test1234
HTTP/1.1 400 Bad Request
Content-Length: 36
Content-Type: application/json; charset=UTF-8
Date: Thu, 09 May 2019 04:33:59 GMT

{
    "message": "Email not verified yet"
}
```

Run the verify manually, copying the token above.

```
http POST 127.0.0.1:9900/api/v1/verifyemail token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTc0NjIyNDMsImlhdCI6MTU1NzM3NTg0MywidXNlcm5hbWUiOiJqb24iLCJlbWFpbCI6Impvbi5tb2JpbGVkZ2V4QGdtYWlsLmNvbSIsImtpZCI6M30.A5mcwkWlfjBUZ3Tvn0EqD_f0a4iPf7U-eg2aMASnrt7Lzdmp2CAEE5Q69g9HlTzE_oEpM3kOSeGhKYRKksvPTQ
HTTP/1.1 200 OK
Content-Length: 39
Content-Type: application/json; charset=UTF-8
Date: Thu, 09 May 2019 04:35:17 GMT

{
    "message": "email verified, thank you"
}
```

Now you can login.

For users created before the verification feature, or for users whose verification token has expired, you can request a new verification email.

```
http POST 127.0.0.1:9900/api/v1/resendverify email=me@gmail.com
```

## Password Reset

A forgotten password can be reset by sending a reset link to your email. Using the account created above, let's request a password reset.

```
http POST 127.0.0.1:9900/api/v1/passwordresetrequest email=me@gmail.com
HTTP/1.1 200 OK
Content-Length: 0
Date: Thu, 09 May 2019 04:39:06 GMT
```

This will send the following email:

```
Hi me,

You recently requested to reset your password for your MobiledgeX account. Use the link below to reset it. This password reset is only valid for the next 1 hour.

Reset your password: https://console.mobiledgex.net/passwordreset?token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTczODAzNDIsImlhdCI6MTU1NzM3Njc0MiwidXNlcm5hbWUiOiJqb24iLCJlbWFpbCI6Impvbi5tb2JpbGVkZ2V4QGdtYWlsLmNvbSIsImtpZCI6M30.SzY9EMRBwVnTnkY3jI-5SXtet4ZmqsDyqstFjhJJPtunHffshM2ADxhPDnELyhr1MvNzAydRzgWQRUPj6MqAOQ

For security, this request was received from a mac OSX device using httpie with IP 127.0.0.1. If you did not request this password reset, please ignore this email or contact MobiledgeX support for assistance.

Thanks!
MobiledgeX Team
```

Again, that link should go the UI where the user enters their new password. Then the UI will send MC the token and new password. So instead we'll call the API directly here.

```
http POST 127.0.0.1:9900/api/v1/passwordreset token=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTczODAzNDIsImlhdCI6MTU1NzM3Njc0MiwidXNlcm5hbWUiOiJqb24iLCJlbWFpbCI6Impvbi5tb2JpbGVkZ2V4QGdtYWlsLmNvbSIsImtpZCI6M30.SzY9EMRBwVnTnkY3jI-5SXtet4ZmqsDyqstFjhJJPtunHffshM2ADxhPDnELyhr1MvNzAydRzgWQRUPj6MqAOQ password=test12345
HTTP/1.1 200 OK
Content-Length: 30
Content-Type: application/json; charset=UTF-8
Date: Thu, 09 May 2019 04:41:29 GMT

{
    "message": "password updated"
}
```

Now you can log in with the new password.

```
http POST 127.0.0.1:9900/api/v1/login username=me password=test12345
HTTP/1.1 200 OK
```

For bonus points, you can delete the user and issue the same password reset request above. MC will still send an email to the address you specified, but the contents will indicate that no account exists for that email.

## Locked Users

If users are configured to be created locked (by command below), then an email will be sent to support@mobiledgex.com (or whatever the notify email address is configured to). It is up to the MobiledgeX admin to then unlock the account.

To lock/unlock ALL new users (does not affect existing users) (run as admin):

```
http --auth-type=jwt --auth=$SUPERPASS POST 127.0.0.1:9900/api/v1/auth/config/update locknewaccounts:=true
> or, to disable:
http --auth-type=jwt --auth=$SUPERPASS POST 127.0.0.1:9900/api/v1/auth/config/update locknewaccounts:=false
```

Show configuration:

```
http --auth-type=jwt --auth=$SUPERPASS POST 127.0.0.1:9900/api/v1/auth/config/show
```

To unlock a specific user (run as admin):

```
http --auth-type=jwt --auth=$SUPERPASS POST 127.0.0.1:9900/api/v1/auth/restricted/user/update email=me@gmail.com locked:=false
```

To force verify a user's email manually without email access:

```
http --auth-type=jwt --auth=$SUPERPASS POST 127.0.0.1:9900/api/v1/auth/restricted/user/update email=me@gmail.com emailverified:=true
```
