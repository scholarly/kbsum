Mailkey: a spam-reduction protocol
==================================

status quo
----------

To send email to someone, all you need to know is the recipient's address.
This is good when you want to be readily accessible: just publish your email
address everywhere people will likely see it.  Unfortunately, when you give
the world permission to contact you, you include spammers.  Even if you don't
publish your address widely, spammers can often easily guess what your email
address is.


A simple approach
-----------------

idea: require something more for spammer to send email

e.g. Box Elder School District rejects mail without the text "box elder" in
the subject header.  This works because besd.net doesn't handle enough mail to
show up on the spammers' radar for special treatment, but it is annoying to
legitimate senders and recipients.

Before Bayesian spam filters were widely deployed, some systems automatically
rejected mail from senders not on a whitelist.  A human sender could get his
address whitelisted by passing an "I am human" test indicated by a URL in the
SMTP status line.  In a sense, you had to ask for permission to be heard. This
"worked", but was annoying for both senders and recipients. It used fewer server
resources because the message could be rejected based on just the sender and
recipient, before the actual message had been transfered.  Spammers could
still sneak through by using a whitelisted address as the sender, but this
should be rare.

A slightly better approach
--------------------------

Taking this approach one step further, and recognizing that an email address
is like a capability granting permission to write to your inbox, we go ahead
and turn it into a real capability by making it unguessable -- e.g. a 128 bit
random number, base32 encoded. (From here on I will use `capability`, `cap`,
and `email address` interchangably.) No changes are required to any software:
Knowledge of the email address still conveys the same permission to write to
your inbox.  However, dictionary attacks are no longer feasible for spammers.
Unfortunately, transcribability and memorability just went out the window. (We
may address this later.)  Your mail service provider does need to support the
creation of arbitrary and unlimited-in-number aliases. This is an easy-to-add
feature already supported by many privacy-oriented email service providers.

First, how to you get the capability to the right people? For now, let's just
say you publish it on your web site, protected by a captcha or such. [maybe a
webkey.](http://waterken.sourceforge.net/web-key/)

Of course, your bank is not going to visit your web site to get your email
address. You will have to give it to them. But you can give them a specific
capability to "tag the message as important" so it doesn't get lost in the
haystack.  You can also attach a specific sender to this capability.

What about PayPal? You can give them a specific capability, just like your
bank.  Unfortunately PayPal is very generous in sharing your email with
merchants and advertisers. This is where some software needs to be changed,
and you will need PayPal to cooperate.  You give them a third-party sharing
capability. When a merchant wishes to contact you, PayPal creates a grant
request with the merchant's name and contact address, signs it with their
private key and encrypts it to your public key (which is part of the sharing
cap).  Your server can generate a new capability attached to the merchant's
sending address and send it to the merchant. (preferably encrypted). Of course
it also makes a lot of sense for PayPal to be more careful about sharing,
since their cap on a spammer's mailing list makes them look VERY bad. (I
speak here from experience: PayPal gave my unique 128-bit random email address
to an advertiser within a few days of when I gave it to them.)

Github? BitBucket? Sourceforge?  As a developer, you want other developers to
be able to contact you. You can treat this the same as the PayPal scenario,
except that the third-party requests can come from any member of the service,
not just merchant's you bought stuff from.  As an alternative, you can just
add a link to your own captcha-protected page that will allow anyone to obtain
a unique capability.

All of these capabilities are revokable.  If a spammer gets one of them, you
can just delete it. You also know when and why it was created, so you can
contact the leaker and express your displeasure.

mailing lists/news groups
-------------------------
News groups and mailing list archives have traditionally been the bread and
butter of email address harvesters.

A mailing list manager (a TTP: trusted third party, like PayPal) can create
it's own caps for messages that get published.

    A: join mailing list M with address M@A
    M: creates A@M as an alias for M@A
    B: join mailing list M with address M@B
    M: creates B@M as an alias for M@B
    B: sends message to M@M (the list post address) sender M@B
    M: rewrites M@B to B@M and publishes message to archive, forwards to M@A...
    A: receives message from: B@M reply-to: M@M
    A: replies privately to B@M
    M: forwards A's message to: M@B from: A@M with a link to an introduction page
    B: reads message visits, introduction page, completes captcha
    M: sends the completed share request to M@A
    A: replies directly to Bs new cap A@B with her own new cap B@A, fully introduced.

If a non-subscriber sends email to A@M or B@M, M can have them complete the
captcha *before* forwarding the message.


NNTP does not provide a TTP as the previous scenarios do, so the reply cap in
a usenet message would have to be protected with a traditional
whitelisting/filter approach.  Or, as is common in newsgroups, the reply
address can be invalid, with "I am human" instructions for making it valid.
These instructions could include an introduction URL with a webkey.

    from: My Nickname <invalid-xkjyp63neixjbyts2vycedp3@example.com>
    .....

    remove 'invalid-' or visit
    https://example.com/intro/mynick/#xkjyp63neixjbyts2vycedp
    PGP key fingerprint: .... ....

The SMTP reject message for invalid-... could include the intro URL


Adding PGP
----------

I find it strange that banks are willing to send unencrypted email to their
customers when adding encryption is so easy:  On the same form where you
supply your email address, you can download the bank's PGP key and upload
yours.  Now any message that they send to you is signed by their key and
encrypted to yours. Safe, secure, simple. What more could you ask?

This same approach can be used by anyone with whom you have a business
relationship or "account" where you can log in with a username and password.

If this entity also acts as an "introducer" (e.g. PayPal, Github, mailing-list
manager), it can leverage those keys to make the introduction much more
secure. Instead of just sending plaintext email to your email cap, they can
sign the intro request with their key and encrypt it to your key.  If you
*realy* trust them, they can include the other party's public key in the
request. Then you can respond directly to the third party with the new cap and
a new public key for that relationship (or your normal public key if you
want).

If you can be assured that all email to a given cap will be encrypted and/or
signed with specific keys, you can add those criteria to your filter, even at
the SMTP level (500 Insufficient security). This takes a bit more effort than
FROM and RCPT filtering because you actually have to read the message body to
check who signed it.

As I see it, the biggest problem with this part of the solution is the
usability of current PGP tools.  But if your bank offerred to use PGP, would
you be more likely to want to learn how to use it?  More service providers
offering and promoting this will motivate their clients to take advantage of
it.

