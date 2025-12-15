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

The age of the universe is approximately 13.8 billion years (1.38 × 10^{10} years), so this time is about 10^{17} times the age of the universe (i.e., more than 100 quadrillion times longer).
Of course, our website is protected by a WAF (Web Application Firewall), and all database operations use parameterized queries (For security research purposes, certain endpoints have been intentionally designed to be vulnerable to SQL injection. These paths are securely isolated in a sandboxed environment, and the affected database is entirely separate from the main production system. All data stored in this test database is non-sensitive and carries no real-world value.).
Additionally, we properly escape outputs to prevent XSS, with no template rendering that could allow SSTI (Server-Side Template Injection). There is no file upload functionality (eliminating risks like PHP webshells or viruses), and user input is never displayed publicly (preventing any possible information leakage or virus propagation).
We are also implementing additional CSRF (Cross-Site Request Forgery) protection measures to further enhance security. However, since all sensitive operations—such as decryption and other critical functions—currently require the user to manually enter their password for authentication, CSRF attacks would not be effective even without these extra measures.
