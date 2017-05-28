# Drop
A better written and more portable re-imagining of
[Stash](https://github.com/sheybey/stash).

This version is written in Python 3 and uses a low-security token system for
access rather than a gpg keyring.

# Deployment
 - Create `drop.cfg` in the application root with an 
   [appropriate entry](http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls)
   for `SQLALCHEMY_DATABASE_URI`
 - Install the dependencies, preferrably in a venv:
   `pip install -r requirements.txt`
 - Create the database: `flask db create`
 - Generate a secret key: `flask secret_key`

By default, there is one token with admin permissions: `please and thank you`.
To use a different token, create a new one with admin permissions, log in
using it, then delete the old one.
