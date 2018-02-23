#!yaml|gpg

key: value
list:
- one
- two
- three
multi-line: |
  This is a multi
  line example.
  It could be a private key
  or something similar.
secure_vars:
  api_key: key_value
  password: foo
sub:
  list:
  - one
  - two
  - three
top:
  wilma: betty
