# Contributing

This is a reference implementation, not a maintained open source library.

## What This Repo Is

A snapshot of the OAuth gateway we built for [OpZero.sh](https://opzero.sh), published so others can learn from it. We're sharing the code and the reasoning, not building a community project.

## What This Means

- **Issues for questions are welcome.** If something is unclear in the docs or code, open an issue and we'll try to clarify.
- **Bug reports are appreciated.** If you find a genuine spec compliance issue, let us know.
- **PRs are unlikely to be merged.** We're not maintaining this as a general-purpose tool. Fork it and make it your own.
- **Feature requests won't be implemented.** This solves our specific problem. Your problem may need different trade-offs.

## If You're Using This

We'd love to hear about it. Drop a note in the issues or tag [@ja_cameron](https://twitter.com/ja_cameron) — it's motivating to know this helped someone skip the OAuth pit we fell into.

## If You're Forking This

Go for it. MIT license means you can do whatever you want. Some things you might want to change:

- Upgrade password hashing from SHA-256 to bcrypt/argon2
- Add rate limiting to the registration and token endpoints
- Add email verification for signups
- Implement token scoping (per-tool permissions)
- Add an admin dashboard for managing servers and users
