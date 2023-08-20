---
title: Most Cookies - PicoCTF Writeup
category: writeups
by: Lorenzo Stella
---

# Most Cookies

### Tools used:

***BurpSuite*** 

***jwt.io***

***flask-unsign:***

Command line tool to fetch, decode, brute-force and craft session cookies of a Flask application by guessing secret keys.

---

## Description

![Untitled](/assets/Most Cookies/Untitled.png)

---

## Approach

After downloading the server.py script this is what we are presented with:

```python
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()
```

in plain english, if what you input in the form on the website is in the cookie_names list (aka is a valid cookie name), then you’ll be redirected to /display and “very_auth” will be set to your input

However to then get the flag “very_auth” should have a value of “admin”, the problem is “admin” is not a valid cookie name, so no redirect happens

For now let’s send some input (’snickerdoodle’) and intercept the web traffic that comes from the process using a proxy tool like BurpSuite proxy

![Untitled](/assets/Most Cookies/Untitled%201.png)

The server respond to the POST request by setting the cookie for the next GET request

![POST request and response](/assets/Most Cookies/Untitled%202.png)

*POST request and response*

![GET request](/assets/Most Cookies/Untitled%203.png)

*GET request*

We could try to modify the value of the session cookie from the first POST request (which is the one that grants the redirect) to contain “admin”, then send the GET request to /display with the new modified value for the cookie

To do so we can use a website like [jwt.io](http://jwt.io) to decode the cookie and modify the decoded value

![Untitled](/assets/Most Cookies/Untitled%204.png)

![new cookie with modified value to ‘admin’](/assets/Most Cookies/Untitled%205.png)

*new cookie with modified value to ‘admin’*

However if we try and send the GET request to /display with our new cookie nothing happens

why? → 

Flask signs the cookies with a secret key to prevent tampering, that means we can still read session data but in order to forge a modified cookie, changing the contents of it and sending it to the server is not enough

---

To understand how to move forward we need to take a look at the Flask cookie format

![Untitled](/assets/Most Cookies/Untitled%206.png)

This [article](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce) (by the same person who created **flask-unsign**, the tool we’re about to use) goes into greater detail, for our intents and purposes, we just need to know that the session data is the actual contents of the cookie and the timestamp tells the server when the data was last updated.

Now to the most important part, the hash. 

Before the server sends back your latest session data, it calculates a sha1 hash based on the combination of your session data, current timestamp and the server’s secret key.

Whenever the server then sees that session again, it will deconstruct the parts, and verify them using the same method. If the hash doesn’t match the given data, it will know it has been tampered with and will regard the session as invalid.

---

All we have to do is find the secret key so that when we’ll forge a new cookie the hashes will match

Lucky for us, upon closer inspection of the code we notice that the secret key is chosen at random among the values of the cookie_names list

```python
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)
```

So we can use a tool like **flask-unsign** to find the secret key and then sign a new forged cookie with it

![Untitled](/assets/Most Cookies/Untitled%207.png)

this command fetches the cookie in the session of the website specified and brute forces the secret key with a list of possible keys contained in “wordlist.txt” (a file I created with the values of cookie_names)

Our secret is ‘butter’

Now we can forge a new cookie with “very_auth” = “admin” and our newly found secret key

![Untitled](/assets/Most Cookies/Untitled%208.png)

All that’s left to do is send the GET request to /display to the repeater in BurpSuite and replace the cookie value with our new forged cookie

![Untitled](/assets/Most Cookies/Untitled%209.png)

The flag is: picoCTF{pwn_4ll_th3_cook1E5_dbfe90bf}