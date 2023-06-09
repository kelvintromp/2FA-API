# 2FA-API

This API was made to be the bridge for 2FA between the login of a webapp and an API handling database requests.

The 2FA API uses 4 modules:<br />
Express: Node.js web application server framework.<br />
Body-parser: middleware that parses the JSON, buffer, string, and URL encoded data of incoming HTTP POST requests and exposes them as req.body before they reach handlers.<br />
Speakeasy: Secret and one-time passcode (OTP) token validator for two-factor authentication.<br />
Fetch: By default, node doesn't have fetch, which is used for requests to a database API.

The 2FA API listens on multiple routes for client POST requests. POST is deliberately chosen as it is a little safer than GET because the parameters are not stored in browser history or in web server logs, nor is any data parsed along in the URL. Which makes it preferable for requests involving sensitive information.

The way the 2FA API routes operates:
api/register: a POST request on this route containing the user’s unique ID will have the API generate a temporary secret that is returned to the client for display as QR code and plain code.

Whilst secrets should normally not be sent to the client, it is unavoidable in this case as it is required for the user to be able to add his account (the secret) to Microsoft Authenticator (or any other OTP token generator).

If the user (checked against the user’s unique ID) already has a secret the API will not generate a new one and instead simply return that one already exists. The page will then redirect the user to the normal validation page for 2FA which simply asks for Microsoft Authenticator’s token, and nothing else.

api/verify: a POST request on this route containing the user’s unique ID in combination with the temporary and, and an OTP token generated by Microsoft Authenticator will have the API verify whether this token is correct.

The temporary secret lets Speakeasy know which server-side token the provided client-side should be checked against.

Lastly the API returns either “verified: true” or “verified: false” depending on whether the token is correct or not.

api/validate: this route operates mostly the same as the api/verify route. The exception is that instead of obtaining the user’s temporary secret from the request body, it will obtain the user’s permanent secret from the main database through a request made to the database API. This will return either “validated: true” or “validated: false”.
