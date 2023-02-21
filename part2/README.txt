Project 2 Part 2: Defenses

------------------------------------------------------------------------------
Alpha
------------------------------------------------------------------------------
The defense of choice in preventing Exploit Alpha is strictly defining valid
usernames. We define a valid username as not having the characters '<' and '>'
to prevent script execution. This is user-friendly because usernames typically
have restrictions on allowed characters. If we detect those characters (or
their encoded equivalents), we render an error to the user.


------------------------------------------------------------------------------
Bravo
------------------------------------------------------------------------------
The defense of choice in preventing Exploit Bravo is using a Cross-Site Request
Forgery (CSRF) token. We generate the token on the server and store it in the
session cookie. We also pass to the transfer/form view as a hidden input field.
When the user submits the form, we check the body of the request sent and see
if the token in the body matches the token in the session cookie.


------------------------------------------------------------------------------
Charlie
------------------------------------------------------------------------------
The defense of choice in preventing Exploit Charlie is implementing a Hash-Based
Message Authentication Code (HMAC). First, we generate a random secret key that
is stored on the server. When there are changes to the cookie (e.g., attributes
loggedIn or account) that are made on the server, we generate a signature/HMAC
and add that to the cookie as the field HMAC. When we receive a cookie from
the client, we verify that recalculating the MAC from the data sent by the
client is equivalent to the HMAC field. If we detect cookie tampering, we log
the user out.


------------------------------------------------------------------------------
Delta
------------------------------------------------------------------------------
The defense of choice in preventing Exploit Delta is the defense of Exploit
Charlie.


------------------------------------------------------------------------------
Echo
------------------------------------------------------------------------------
The defense of choice in preventing Exploit Echo is SQL parameterization. We
change the SQL command template in the close endpoint to a SQL parameter, which
is the account's username per the session cookie.


------------------------------------------------------------------------------
Foxtrot
------------------------------------------------------------------------------
The defense of choice in preventing Exploit Foxtrot is adding a Content
Security Policy (CSP). We add a CSP header to the method get('/profile') in
router.js. On each request, a random nonce will be generated and added to the
CSP. This allows scripts to run only when they have the correct generated nonce.
We ensure that the showBitBars() function still runs by passing the nonce to its
script in profile/view.ejs.


------------------------------------------------------------------------------
Gamma
------------------------------------------------------------------------------
The defense of choice in preventing Exploit Gamma is a combination of
randomizing the durations of the get_login function and adding another CSP.
We sleep for random amounts of time for each instance of checkPassword(). To be
thorough, we sleep for slightly longer random amounts of time for invalid
passwords, since checkPassword() on invalid passwords runs faster. We also
add a CSP to the method post(/'post_transfer') to ensure that no malicious
scripts are run for anything related to transfer.
