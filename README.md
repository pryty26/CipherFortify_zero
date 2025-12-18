# CipherFortify_zero
A website countain many cybersecurity tools, for exemple a password vault. 
Your password + our random key = true privacy. We never store your password. Your key. Your data. Your control.
all_function.py: Contains login, register, WAF (Web Application Firewall), and login verification functions.
app.py: The main application file built using Flask.
user_secrets.py: Provides encryption, decryption, find all encrypted data, and delete data functions.
This three file is the three main file of my website.

The presentation of this website:
The all data has encrypted by password+ServiceSecretKey+RandomSecretKey+SpecialEncryption+Hashlib
The encryption is Symmetric encryption
But we won't make public or SecretKeys and we won't store your password too.
So your encrypted data is safe
Even if our database has been stolen the attacker can't decrypt your data, because he haven't serverSecretKey, SpecialEncryption and your password.
Of course all the website has https too.
If you wanna ask:
Why it's safe?
Let me give you the answer:
Assume the server key is a 50-character random string (high-entropy "garbled" data), and the stored form is SHA-256(key + password) or a similar concatenation (common in certain password storage or verification schemes).
In the case of purely attempting to crack the server key:
The total number of attempts required: 10^{56} (on average, half of the search space needs to be covered, i.e., approximately 5 × 10^{55} attempts, but the order of magnitude remains the same).
Theoretical average time = 5 × 10^{55} / 10^{21} = 5 × 10^{34} seconds.
Conversion:

1 year ≈ 3.156 × 10^7 seconds
Number of years ≈ 5 × 10^{34} / 3.156 × 10^7 ≈ 1.58 × 10^{27} years

The age of the universe is approximately 13.8 billion years (1.38 × 10^{10} years), so this time is about 10^{17} times the age of the universe (i.e., more than 100 quadrillion times longer).This places the attack far beyond any practical or theoretical capability.
Comprehensive Protection Measures
Transport Security: All connections are enforced via HTTPS (TLS).
Application Security:
Protected by a Web Application Firewall (WAF).
All database queries use parameterized statements to prevent SQL injection.
Output encoding is applied to mitigate XSS risks.
No user file uploads are permitted, eliminating related attack vectors.
CSRF protections are in place, and all sensitive operations require explicit password re-authentication.
Transparency Note: For educational purposes, a few isolated endpoints in a sandboxed environment are intentionally vulnerable to SQL injection. This test environment uses a separate database containing only non-sensitive, valueless data and poses no risk to the main production system or user data.



Attension!The whole website is opensource,collaborative, freely usable and modifiable
Everyone is welcome for example make a issue!
