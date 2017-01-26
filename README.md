* Team-Secrets *

This is a command line utility for sharing secrets (passwords, api keys, etc) among a team and with servers. Store your passwords in a git repository and track changes without keeping plain text sensitive data.

** How Does It Work? **

All secrets are encrypted with AES symmetric encryption and stored in a YAML file. The encryption key is then encrypted for each user of the system using public-key, asymetric encryption. Then each user can decrypt the master key and reveal secrets or add new ones when needed. Everything is signed to prevent tampering and encryption keys are rotated when users are added or removed.

With the tag feature, you can filter credentials which has many different use cases. For isntance, use tags to differentiate between secrets used in DEV, QA and PROD.

To start a new repo for your secrets:
`team-secrets init`

You'll be the first user and you'll be prompted for a user name to use and the path to your public key. Your public key will be added to the project, along with the initial YAML files.

You can then add new users:
`team-secrets users add`

And, new secrets:
`team-secrets secrets add`

Then, commit your changes and push to your central repository. Anyone you add will be able to access the secrets and manage users with through their private key.

Retrieve all secrets:
`team-secrets secrets list`