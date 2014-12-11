
## SSHCRYPT

Encrypt and Decrypt files using only SSH RSA Keys!

Planned Features
- CLI arguments! - DONE
- Encrypt to ALL RSA keys in an authorizedKeys file
- Encrypt to ALL RSA keys in an user's github account
- Releases
- If private key has a password, ask for it securely
- ssh-agent support?

Note.
- Can only encrypt to one key at a time, will support many later
- Does not yet supported password protected private keys


## INSTALL AND TEST
```sh
$ go get -u github.com/totallylegitbiz/sshcrypt
$ sshcrypt --help
Usage of ./sshcrypt:
  -d=false: Decrypt file instead of encrypting
  -in="-": Input file
  -out="-": Output file
  -privKey="~/.ssh/id_rsa": Private Key file (Decrypting)
  -pubKey="~/.ssh/id_rsa.pub": Public Key file (Encrypting)

$ echo hello | sshcrypt | sshcrypt -d
hello
```

## Why?

The other day, my friend was asking how to encrypt a file public key. I assumed he
meant PGP key, but he was actually talking about ssh keys. A quick google shows
people have asked this question before, with kind of lack luster answers.

The majority of ssh keys are actually RSA keys, which is good as they are the only
type of ssh keys which can also encrypt. It also happens to be the majority of PGP
keys are also RSA keys. As a result, the underlying encryption of PGP messages and
authenticating to a server are usually the same.

For some reason, many people think that PGP is either hard or complicated. GnuPG
is a pretty fantastic tool, but usability is not its strong suit. To the average
user, the PGP trust model is both confusing and complicated. Unless you are in a
work environment or surrounded by people who actively care about PGP and it's
features, people misuse it and don't appreciate it.

A regular use case for PGP is Alice wants to send Bob a message that no one else
can see. Alice ask's Bob if he uses PGP, bob says no. Alice then spend's 30 minutes
convincing Bob that PGP is good, and another two days teaching Bob how to use GnuPG.
After much frustration, the original encrypted message is sent and decoded successfully.
WOOT! Bob never uses PGP again, and Alice wants an easier way.

On the other hand, ssh-keys are very popular. Bob uses github, Alice can easily get all
of Bob's ssh public keys at https://github.com/bob.keys. Very handy for giving access
to a server, but not for sending files, even though all those keys use the exact same
encryption scheme as the PGP key Bob created for Alice earlier.

Why someone hasn't made a simple tool to use those keys to send someone is a mystery.
That's what this tool hopes to solve.


## FAQ
##### Q. Is this an orginal idea?
A. No, but this is the first tool of its kind. AWS actually encrypts their window instance's password using sshkeys.

##### Q. Is this as secure as OpenPGP?
A. Depends. PGP has a great many features. The hard part is KNOWING that a key actually belongs only to the person you are sending it to. The PGP trust model has a solution to that, but no body really uses it.

Also, sshcrypt can't sign messages. So if you send someone a message, you can be reasonably sure that only they will be able to read it, but someone may be able to completely replace the message, and your recipient would be none the wiser.

##### Q. Can I sign a message with my SSH Private Key?
A. This is technically possible. It would require encoding more information about the sender and where to get his public keys from. Although, if this is a desire for you, maybe upgrading to full blown PGP is right for you.

##### Q. Doesn't keybase make PGP easy?
A. No, it does not, for a few reasons.
- It still requires people to setup and figure out PGP, taking at least 10 minutes for an enthused person to complete.
- You verify you account by posting some code to github, as such the keys there are as valid as the ssh keys from github.
- Key's created though keybase have a key identifier of keybase/username which breaks almost all other PGP tooling.

##### Q. Where can I tell you did something wrong?
A. Create an issue or a pull request. You're likely right.

