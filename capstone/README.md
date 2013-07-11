
## Abstract

Passwords are the most commonly used method of authentication.  While there are many issues with the way passwords are used today, among the most serious are that many people (1) select weak passwords, and (2) reuse those weak passwords in many different contexts.  One solution to this problem is to encourage the use of password managers, which generate a unique, high-entropy password for each security domain and keep all of these passwords in a single store encrypted with a single well-chosen password.  Remembering dozens of strong passwords is not possible for most people, but remembering one is possible.
This project will explore some of the problems with current password managers and propose solutions to overcome them.

keywords: password habits, password manager, single sign-on, authentication protocol


# Capstone Proposal Summary 

Passwords are the most commonly used method of authentication.  While there are many issues with the way passwords are used today, among the most serious are that many people (1) select weak passwords, and (2) reuse those weak passwords in many different contexts.  One solution to this problem is to encourage the use of password managers, which generate a unique, high-entropy password for each security domain and keep all of these passwords in a single store encrypted with a single well-chosen password.  Remembering dozens of strong passwords is not possible for most people, but remembering one is possible.

This project will explore some of the problems with current password managers and propose solutions to overcome them. The project deliverables will include a new password manager prototype with a browser helper to manage web logins.

### Threat Model
Anyone who claims that a system is "secure" must define the expected threat model and what constitutes a failure of the system.  Our goal for project is to protect against an attacker with the following capabilites:

 1. attacker has complete control of the network between client and server (Delov-Yao,1983) 
 2. attacker has access to hardware that can perform MD5/SHA hashes very quickly
 3. attacker may be able to obtain hashed password file from a server
 4. attacker *may* be able to obtain a copy of the encrypted vault.

Failure can be described on three levels

 1. minimal - attacker obtains credentials sufficient to impersonate user in one low-value security domain.
 2. serious - attacker obtains credentials sufficient to impersonate user in multiple security domains, or a single high-value domain.
 3. complete - attacker is able to obtain and decrypt password vault.

We will assume that the defender is competent and motivated -- he is willing and able to follow our recommendations.  After we have implemented them, we can consider how to make them more accessible to the people with less motivation and techincal expertise.

We will not address physical or environmental monitoring attacks.


## Review of Current Solutions

Currently available password managers fall into four broad categories:

First, many modern browsers are able to remember passwords that the user has typed in. These built-in password managers are easiest to use but least secure.  The biggest problem is that, by default, the user does not have to enter a master password to access the data.  This means that it is "encoded", not "encrypted".  Anyone with access to the browser also has access to the stored passwords.

Mozilla Firefox stores passwords in two files in the user profile directory. `key3.db` holds the encryption key and `signons.sqlite` holds the passwords. Unfortunately key3.db is not protected by default. But if you set a master password, you really can't get them back without it. [https://support.mozilla.org/en-US/kb/Recovering%20important%20data%20from%20an%20old%20profile#w_passwords]
[https://support.mozilla.org/en-US/kb/reset-your-master-password-if-you-forgot-it]
::
	https://support.mozilla.org/en-US/kb/create-secure-passwords-keep-your-identity-safe
	They are trying, but this is very bad advice that I see repeated many different places.
	What percentage of the people reading this article are going to follow this advice to the letter?  What is going to happen to their other accounts when the first one is compromised? The problem with security through obscurity is that it fails dramatically when the secret is no longer obscure.

Internet Explorer stores passwords in two different places, which are normally only accessible to the owner and to any adiministrators. Excellent.  Unfortunately, the encryption key is actually the URL of the website the password is for (DOH!).  And, unless the entire hard disk is encrypted, getting Adminitrator privileges on a Windows machine is pretty easy if you have physical access. (Which our attacker does not have, but with all things considered, the protection is pretty weak.) [http://stackoverflow.com/questions/3023561/where-does-internet-explorer-store-saved-passwords#3024795] I will give IE credit, however, for not blatantly *showing* anyone the passwords, as Chrome does.

Google Chrome has several different password stores. On Windows, it uses the same API that IE does (weak). On MacOS, it uses the system Keychain Access (just like Safari and other well-behaved apps that need to store secrets). Keychain Access encrypts the secrets (but not the metadata) with TripleDES (still respectable, but not considered a strong cipher by modern standards).  However, by default the store is keyed from the same password you use to log in. The wisdom of this is debatable.

The scary code in Chrome is for Linux. It has support for gnome-keyring and kwallet, which are probably at least as secure as Keychain Access. However, the encryption code for the *default* store looks like this:

        in chromium/src/chrome/browser/password_manager/login_database_posix.cc 

	// TODO: Actually encrypt passwords on Linux.

	bool LoginDatabase::EncryptedString(const string16& plain_text,
					    std::string* cipher_text) const {
	  *cipher_text = UTF16ToUTF8(plain_text);
	  return true;
	}

OOPS! The API is in place, but it does nothing. The comment is actually funny in a sick way.

I will give Google an Honorable mention for [wanting to improve the situation][http://www.pcworld.com/article/250120/google_working_on_password_generator_for_chrome.html], but since that was sixteen months ago, and I haven't seen anything appear in the releases, I won't hold my breath.

The linked article http://www.pcworld.com/article/181347/a_single_sign_on_for_all_your_websites_google_hopes_so.html only confirms that OpenID is all but dead.  You can use a Google OpenID from other sites, but you cannot create a account on any of Google's sites using another OpenID provider.  It seems Google will let you use OpenID as long as they are holding the keys.  Which completely defeats the purpose. Flickr will accept Google or Facebook or Yahoo, but no others.)


### Web-based Password Generators
 All of the "web-based" password managers I found were client-only applications: no unencrypted data was ever stored on a server.  Lastpass experienced and quickly patched a breach due to a XSS attack that revealed login metadata but no passwords.  This validated their decision to do all decryption on the client side only, and suggests that even the metadata should not be stored.
  The light-weight web clients are mostly password generators with no storage. Typically, you enter your master password and the small javascript program hashes it with the domain of the website to create a unique password for that site.  While this is better than what most people do, and it is slightly better than the advice being given by many parties [https://support.mozilla.org/en-US/kb/create-secure-passwords-keep-your-identity-safe]
, it is definitely not appropriate for high-value passwords.  )

### Browser Extensions
 such as lastpass, raise the bar by allowing you to protect your data with a strong password and strong encryption.  All decryption happens on your computer, but it is accessible from any computer because the database is synchronised with a copy on their server.

### Standalone Password Managers

KeePass, Tk8, and 1Password are among the many standalone programs that you can install to store your data on your computer. You can keep the database synchronised across many computers by using a cloud-based storage system like DropBox.




## Strategies

### NEVER Reuse Passwords

I cannot emphasize this too much.  While the traditional Dolev-Yao model assumes that the network is compromised but the nodes are secure, *this is not a reasonable assumption today* and probably never will be.  Except in a wireless network, an attacker cannot control a link without first controlling a node.  Assume that your server administrator is honest and competent but overworked, possibly naive, and certainly fallible.  Assume that the server *will* be compromised sooner or later. (If you want to test your security, brag on IRC about how your server has bank account details for 10,000 customers.)  Reusing passwords under this threat model is utterly foolish.

Why is this really such a problem?  Why can't we assume that the server will stay safe?


[http://blog.crackpassword.com/2013/02/yahoo-dropbox-and-battle-net-hacked-stopping-the-chain-reaction/]

leaked_password_lists_and_dictionaries. (2012, Jul 13). In *The Password Project*. Retrieved 21:26, July 10, 2013, from http://thepasswordproject.com/doku.php?id=leaked_password_lists_and_dictionaries&rev=1342207197.


[Steve Gibson's password haystack strategy][https://www.grc.com/haystack.htm] is certainly workable for a password that you know will be protected by a good slow key derivation function.  It is not, however, appropriate for a password that *might* be stored or seen in plain text -- i.e. any server-side password.  If you use the same padding pattern for all of your passwords, as Steve suggests, and your pattern gets revealed by a careless application developer, a smart cracker can use that pattern against you. He does warn against this, but not strongly enough, in my opinion.


### Use Random Passwords

Each security domain should have a long, unique, random password.  Uniqueness prevents a compromise of one domain from leading to compromises in others.  Randomness prevents success through an online dictionary attack.  We assume that administrators will rate-limit and block any high-speed online attack, so such will work only against very poor passwords.
Length and complexity forces the attacker to use brute-force attack if he obtains a hashed password file.  Once we have committed to storing each password, generating unique random passwords is easy. The complexity is only limited by the rules imposed by the security domain's policy. For your entertainment, I present the following less-than-optimal password complexity policies:

Hunt, Troy (2011), "Who's Who of Bad Password Practices", [http://www.troyhunt.com/2011/01/whos-who-of-bad-password-practices.html]
[Visa/Wells Fargo weak password policy][http://blog.zorinaq.com/?a=2011-m05#e54] makes the password way too short.
[Godaddy][http://support.godaddy.com/help/article/2653/generating-a-strong-password] allows a good long password, but restricts the alpabet to four out of 33 possible special characters.

### Use An Expensive KDF

A key derivation function (KDF) is a special cryptographic tool that turns your weak, memorable, low-entropy password, into something that at least appears to be random -- something that is usable as a secret key for encrypting data.  And it does this in a way that is not generally reversable. We want this function to be slow and expensive because, you know your password and only have to use the function once for each time you unlock your database, so waiting 1 or 2 seconds is not a big deal. However, the attacker has to guess your password, and if you chose it well, he will have to guess it many times. The slower that function is, the longer it will take for him to guess your password.

There are three main candidates for your KDF.  The standard one that most people use nowadays is called PBKDF2. Most people use it with SHA-1, a very fast hash function.  The problem is that the attacker's super cracking hardware is *designed especially for doing SHA-1 **very quickly** -- not what you wanted to hear.  The second choice, `bcrypt` is *much* slower to compute.  The third choice, a relatively new invention, is called `scrypt`.  What makes scrypt special is that not only can you make it very slow, but you can also make it take up a lot of memory -- not what the attacker wanted to hear: his super cracking hardware doesn't have very much memory because it would be too expensive.  What scrypt does is force the attacker to use normal computers to check each password guess. So unless he *really* wants *your* password, he will probably say "Scrypt? Never mind. I'll go hack someone who uses SHA-1"

We assume that if the attacker has obtained the password file, he also has access to any other unencrypted data stored on the same server, so a good password no longer benefits us. (The attacker has already *won* this domain.)  However, it may benefit others who do not use unique passwords because it will absorb some of the attacker's time, epecially if the passwords are hashed with an expensive KDF. The attacker will only attempt to crack all of the passwords in the hope of obtaining credentials that are reused.  If the hashes are created with scrypt or bcrypt, the attacker may simply give up and move on to lower-hanging fruit, as his hardware is designed for simpler hash functions.

### Encourage the Use of Secure Authentication Mechanisms

SRP with scrypt is ideal:  1) there is never a need for the plaintext password to traverse the network.  2) the verifier stored by the server is expensive to crack.
Client certificates (X.509 or PGP or SSH) are also a good option, but may require a more complex infrastructure.


### Use TLS Carefully

If the security domain adminstrator insists on using a plaintext authentication system, it should at the very least be protected by TLS.  If not, then it must be a very low-value site, so there is really nothing to be done beyond using a unique password.

For higher-value sites, we can reject weak cipher suites suggested by the server, which MAY be controlled by the attacker. We can configure TLS to prefer ephemeral session keys over long-term keys. (Perfect Forward Secrecy.)

If the attacker also has control of which root trusted certificates the browser trusts (e.g. corporate IT department), he may establish a rogue TLS proxy that can transparently decrypt all TLS traffic.  We can partially adress this by rejecting any certificate that is not known-good by our own criteria.  While this constitutes a denial of service, it can prevent disclosure of credentials.  In general, it is unwise to use high-value domains using a client that you do not absolutely control.


### Use Hardened Client Configuration for High-Value Sites

To protect credentials of high-value sites, we can use a hardened browser configuration.  This includes disabling non-essential plugins and scripts, and strictly limiting which domains the browser instance can access.  As mentioned above we can manually configure which certificates are trusted and reject all connections via non-trusted certificates.  All non-hardened configurations should be prevented from accessing the high-value domains.

Even for other sites where disabling plugins and scripts may not be desireable, limiting session length can reduce the risk of BEAST-like attacks from a man-in-the-browser.  Limiting the number of open tabs can encourage shorter sessions. If the user can only open, for example, five or nine tabs, he is much less likely to leave any open and unattended for long periods of time.  Some users have reported that this also helps them focus better and be more productive.  Research should allow us to come up with a more productive way to use tabs than just allowing them to pile up until they collapse.

   active man-on-the-server -- compromise of one security domain MUST NOT lead directly to compromise of others: never reuse a password
   active man-in-the-browser -- this can only be prevented by a hardened browser configuration and may be worthwhile only for high-value sites. Avoiding long sessions can lower the risk of BEAST/CRIME attacks
   active TLS proxy with rogue certificates -- browser helper can verify and pin known-good certificates for high-value sites and can Notify the end user of a bad ceritificate, but cannot in general bypass the rogue proxy (e.g. inside corporate firewall.)

We will not address:
   environmental monitoring: keyloggers, shoulder surfing
   rubber-hose attacks


The attacker is considered partially successful if he obtains enough information to impersonate the user in a particular security domain.
The attacker is considered very successful if he obtains more than one set of credentials for the user.
The attacker is considered completely successful if he is able to obtain and decrypt any part of the vault.
Merely obtaining the vault or any server-side password file is not considered a success.


	protect communication with careful use of TLS 
	prefer authentication systems that avoid plaintext passwords traversing the network
		secure key exchange strategies (e.g. SRP) 
		not challenge-response protcols that require storing plaintext password on the server.
		
   offline brute-force or dictionary attack on a password database from a compromised server: 
	

	never reuse a password
	use a long, high-entropy password
	encourage adminitrators/app developers to use a slow key derivation function for hashing the stored password verifiers, e.g. bcrypt, script (for the sake of people who re-use passwords, not for us.) 
	we should make a brute-force attack against the verifier approximately as expensive as a direct attack on the secret key
		overkill: we assume he already has access to the server and any unencrypted user data stored there.
		once the server is compromised, learning the password will not gain him anything, because it is never used anywhere else.

   offline brute-force or dictionary attack on the master password vault (this will allow us to store the vault in an untrusted location in the cloud)
	use a very long, diverse password - dictionary attack must fail
	use an expensive key derivation function (scrypt,bcrypt)
		we should make a brute-force attack against the KDF approximately as expensive as a direct attack on the secret key
		if he decides to brute-force the key, make him try each key on each block of the file
	allow multiple passwords, a-la TrueCrypt hidden volume
	haystack: size of the file should not depend on the number of passwords stored in it.

suggested length of 3 to 5 pages (1000-1600 words)


issues:
 simplicity: trusted code must be reasonably auditable.
 acceptable user experience
    it should "just work"
    it would be nice if there were a standard way websites could tag "login", "registration", and "password change" forms
	TLS-SRP and TLS with client certificate could handle the "login" part
    user can set re-prompt timeout (integrate with screen locking)
 minimize exposure of key material
    ideal: key material should stay within address space of the password manager.
    reality: most websites require the secret to traverse the network (usually in some encrypted form).
    secure IPC (DBus?)
 user controls (sets policy) where the secrets are stored
    e.g. NOT on lastpass.com
 SSL eavesdropping proxies


## Review of Other Work 
suggested length of 2 to 3 pages (600-1000 words)

### password insecurity
Microsoft's "study"
GRC Gawker, Sony

### SSO solutions

 * Kerberos
 * Factotum
 * OpenID
 * ssh-agent

### password managers
1password
keepassX
lastpass
seahorse, including DBus interface with encrypted IPC

### encrypted storage
LUKS
gnupg/pgp
TrueCrypt

### Key derivation functions
PBKDF2
bcrypt
scrypt

### SSL snoopers
grc.com

## Rationale and Systems Analysis 
suggested length of 2 to 3 pages (600-1000 words)

See Strategies above.

## Goals and Objectives 

suggested length of 5 to 8 pages (1600-2600 words)

Keep the passwords as safe as possible, but no safer. (Recognize the limitations of the underlying platforms.)
protect passwords from disclosure to malicious parties, specifically via the attacks listed in Section1.

Do not trust the browser: i.e. do not allow the secret into the browser's address space.
(OBJECTION: but we eventually have to trust the browser to render the secured content. OVERRULED: yes, but we don't have to trust every plugin and extension. We need strict control of what information leaks into which security domains.  Lastpass (and most other extensions) has "access to all of your data on all of your sites" ("Trust us, we are not evil") ("I'm Bruce. Fish are friends, not food.") Indeed all of this information is available to any process that can read the browser's memory, which includes malicious scripts running shell code through a buffer overflow.  The idea is to minmize -- and carefully audit -- the code that must be trusted with the key material.)

Educate the end user on the benefits and limitations of the system.

Allow the end user to control access to the database.


## Project Deliverables 

	suggested length of 5 to 8 pages (1600-2600 words)

This project will deliver a prototype password manager that meets the goals stated above, specifically:

 * provide a secure store for user secrets (hereafter "the vault")
 * provide a secure key derivation function to obfuscate the master passwrd (scrypt)
 * lock any application memory that holds secrets
 * provide a browser helper to
    1 accept a login request from the browser
    2 (optionally) prompt the user: make sure she actually initiated the request, not a malicious XSS hacker
    3 interact with the target website to create an authentication token
    4 return the token to the browser
 * the browser helper should also handle registration and password changes:
    1 browser retrieves registration form
    2 user fills out form, omitting the passwords
    3 browser passes partially-completed form to helper
    4 helper generates appropriate high-entropy password and stores it in the vault
    5 helper posts the completed form to the target web site and returns the result to the browser

One way to implement the browser helper is as a proxy server. One benefit of this implementation is that it would allow extended verification of the SSL certificate fingerprints as described by Steve Gibson. (OBJECTION: Do I trust this software to be an SSL proxy? Irrelevant: you are already trusting it to store all of your passwords.) It could also store secure cookies.??? (How many AJAX apps require access to that cookie? research Javascript restrictions on cookie access.)

The prototype will run under Linux and interact with surf (http://surf.suckless.com/). It will be able to log in to Google, Amazon, Paypal, Ebay, Twitter, wordpress.com, and America First Credit Union.

A later protoype will support cloud-based storage of the vault. (orthogonal feature.)

## Project Plan and Timelines

The initial prototype shall be completed by 31 July 2013.
Research: 3 days
UX design: 2 days
detailed specification: 3 days
implementation and testing: 8 days


## Appendix 1: Competency Matrix


## Appendix 2: Password Managers
There is obviously a demand for this technology.  DuckDuckGo search for password manager produced an advertisement for RoboForm.
Google search produced 3 ads: manageengine.com/PasswordManagerPro, lockerhq.com/password-manager, and my1login.com
Bing also produced: thycotic.com/Secret-Saver, pleasantsolutions.com/PasswordServe, and a device sold on acornonline.com


## References

Dolev, D.; Yao, A. C. (1983), "On the security of public key protocols", *IEEE trans. on Information Theory*, IT-29: 198–208






http://lifehacker.com/5529133/five-best-password-managers
http://lifehacker.com/5944969/which-password-manager-is-the-most-secure
http://lifehacker.com/5937303/your-clever-password-tricks-arent-protecting-you-from-todays-hackers
http://lifehacker.com/5876541/use-this-infographic-to-pick-a-good-strong-password
http://lifehacker.com/5796816/why-multiword-phrases-make-more-secure-passwords-than-incomprehensible-gibberish
http://lifehacker.com/5785420/the-only-secure-password-is-the-one-you-cant-remember



http://www.infoworld.com/t/data-security/amazon-ec2-enables-brute-force-attacks-the-cheap-148447
http://s3.amazonaws.com/dnr/dotnetrocks_0626_rob_conery.pdf What's wrong with OpenID? privacy, single point of failure, people still use weak passwords. easy phishing attack for naive providers.


http://rcottrell.com/blog/a-smart-browser/
https://www.grc.com/sn/sn-297.htm	
