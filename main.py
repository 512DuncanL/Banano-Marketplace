# Import libraries
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pymysql
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
import re
import multiprocessing
import time
import decimal
import math
import uuid
from bananopie import RPC, Wallet

app = Flask(__name__)

pymysql.install_as_MySQLdb()

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://admin:password@localhost:3306/bananomarketplace"

app.config["SECRET_KEY"] = "[ENTER A SECRET KEY]"

app.config["REMEMBER_COOKIE_DURATION"] = 86400 # Stay logged in for 24 hours

db = SQLAlchemy()

ph = PasswordHasher()

login_manager = LoginManager()
login_manager.init_app(app)

rpc = RPC("https://kaliumapi.appditto.com/api")

banano_account = Wallet(rpc, seed="[ENTER YOUR BANANO WALLET SEED]", index=0) # Create banano account object

# Create function to easily round down numbers to 2dp
def roundDown(num):
    return math.floor(float(num) * 100) / 100.0

# Create function to detect and receive new incoming transactions every minute
def autoReceive():
    while True:
        with app.app_context():
            try:
                blocks = banano_account.get_receivable()["blocks"] # Get receivable blocks
                for block in blocks:
                    banano_account.receive_specific(block) # Receive banano
                    
                    sender_address = rpc.get_block_info(block)["block_account"] # Get sender address from each block
                    
                    user = Users.query.filter_by(address=sender_address).first()
                    user.balance = user.balance + decimal.Decimal(roundDown(rpc.get_block_info(block)["amount_decimal"]))
                    
                    db.session.commit()
            except Exception as e:
                print("Receive failed:", e) # Log failure and reason to console
                
        time.sleep(120)

# Structure of Users database
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.DECIMAL(20, 2), nullable=False)
    address = db.Column(db.String(250), unique=True, nullable=False)
    ban_reason = db.Column(db.String(250), nullable=False, default="")
    ban_timer = db.Column(db.Integer, nullable=False, default=0)

# Structure of Listings database
class Listings(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    status = db.Column(db.String(20), nullable=False)
    listing_type = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(2500), nullable=False)
    merchant = db.Column(db.String(250), nullable=False)
    client = db.Column(db.String(250), default="")
    price = db.Column(db.DECIMAL(20, 2), nullable=False)
    contact = db.Column(db.String(250), nullable=False)

db.init_app(app)

with app.app_context():
    db.create_all()

# Start auto-receive thread
receive = multiprocessing.Process(target=autoReceive)
receive.start()

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html'),401 # Handle error 401 unauthorized (user tries to access page where login is required)

@app.route("/", methods=["GET", "POST"]) # Index page, returns page with listings
def index():
    if request.method == "GET":
        listings = Listings.query.filter(Listings.status == "Created", Listings.listing_type == "Buy").all() # Get buy listings by default, returns listings with Created status only (Accepted or Completed not returned)
        return render_template("/index.html", listings=listings, filter="Buy")
    else:
        filter = str(request.form.get("filter") or "") # Get filter type from form, replace None with "" if necessary
        
        if filter not in ["Buy", "Sell"]:
            filter = "Buy"

        if filter == "Buy":
            listings = Listings.query.filter(Listings.status == "Created", Listings.listing_type == "Buy").all() # Same as listing query above
            return render_template("/index.html", listings=listings, filter="Buy")
        else:
            listings = Listings.query.filter(Listings.status == "Created", Listings.listing_type == "Sell").all() # Same as listing query above, but Sell
            return render_template("/index.html", listings=listings, filter="Sell")
        
@app.route('/logout') # Log out user
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route('/account')
@login_required
def account():
    return render_template("/account.html")

@app.route('/accept', methods=["POST"]) # Accept listing
@login_required
def accept():
    id = str(request.form.get("listing") or "")

    listing = Listings.query.filter(Listings.id == id).first() # Get first listing that matches the id

    # Check if listing is valid
    if not bool(listing): # Check if listing exists
        flash("Listing does not exist")
        return redirect(url_for("index"))

    if current_user.ban_timer == -1: # Check if user is permanently banned
        flash("You have been permanently banned for: " + current_user.ban_reason)
        flash("Banned accounts cannot accept listings")
        return redirect(url_for("display_listing", title=id))

    if current_user.ban_timer > time.time(): # Check if user is still temporarily banned
        flash("You have been temporarily banned for: " + current_user.ban_reason)
        flash("Banned accounts cannot accept listings")
        flash("You will be unbanned in " + "{:0>8}".format(str(timedelta(seconds=(current_user.ban_timer - int(time.time()))))))
        return redirect(url_for("display_listing", title=id))

    if listing.client != "": # Check if listing has a client or not (listing is "" by default)
        flash("You cannot accept a listing that already has a client")
        return redirect(url_for("display_listing", title=id))

    if listing.merchant == current_user.username: # Check if merchant is trying to accept their own listing
        flash("You cannot accept your listing")
        return redirect(url_for("display_listing", title=id))

    if listing.status != "Created": # Check if listing status is Created (Accepted or Completed listings cannot be accepted)
        flash("Listing status must be created to be accepted")
        return redirect(url_for("display_listing", title=id))
    
    if listing.listing_type == "Sell": # Put user balance into escrow
        final_balance = current_user.balance - listing.price
        if final_balance < 0:
            flash("Insufficient balance")
            return redirect(url_for("display_listing", title=id))
        else:
            current_user.balance = final_balance
    
    listing.status = "Accepted" # Mark listing as accepted and add client username to listing
    listing.client = current_user.username
    
    db.session.commit()

    flash("Listing " + id + " accepted successfully")

    return redirect(url_for("display_listing", title=id))

@app.route('/complete_listing', methods=["POST"]) # Complete / finish listing
@login_required
def complete_listing():
    id = str(request.form.get("listing") or "")

    listing = Listings.query.filter(Listings.id == id).first()

    # Check if listing is valid
    if not bool(listing):
        flash("Listing does not exist")
        return redirect(url_for("index"))

    if listing.client == "":
        flash("You cannot complete a listing that has no client")
        return redirect(url_for("display_listing", title=id))

    if listing.merchant == current_user.username and listing.listing_type == "Sell" or listing.client == current_user.username and listing.listing_type == "Buy":
        flash("You cannot complete this listing")
        return redirect(url_for("display_listing", title=id))

    if listing.status != "Accepted":
        flash("Listing status must be accepted to be completed")
        return redirect(url_for("display_listing", title=id))

    merchant = Users.query.filter(Users.username == listing.merchant).first()
    client = Users.query.filter(Users.username == listing.client).first()
    
    if listing.listing_type == "Sell":
        merchant.balance = merchant.balance + listing.price # Move Banano from escrow into merchant account
    elif listing.listing_type == "Buy":
        client.balance = client.balance + listing.price # Move Banano from escrow into client account
    
    listing.status = "Completed"
    
    db.session.commit()

    flash("Listing " + id + " completed successfully")

    return redirect(url_for("index"))

@app.route('/my', methods=["GET", "POST"]) # My listings
@login_required
def my():
    if request.method == "GET":
        listings = Listings.query.filter(Listings.listing_type == "Buy", ((Listings.merchant == current_user.username) | (Listings.client == current_user.username))).order_by(Listings.id.desc()).all() # Filter for listings that involve the current user
        return render_template("/my.html", listings=listings, filter="Buy")
    else:
        filter = str(request.form.get("filter") or "")

        if filter not in ["Buy", "Sell"]:
            filter = "Buy"

        if filter == "Buy":
            listings = Listings.query.filter(Listings.listing_type == "Buy", ((Listings.merchant == current_user.username) | (Listings.client == current_user.username))).order_by(Listings.id.desc()).all()
            return render_template("/my.html", listings=listings, filter="Buy")
        else:
            listings = Listings.query.filter(Listings.listing_type == "Sell", ((Listings.merchant == current_user.username) | (Listings.client == current_user.username))).order_by(Listings.id.desc()).all()
            return render_template("/my.html", listings=listings, filter="Sell")

@app.route('/listing/<string:title>')
def display_listing(title: str):
    listing = Listings.query.filter(Listings.id == title).first()

    if not bool(listing):
        flash("Listing does not exist")
        return redirect(url_for("index"))

    if listing.status == "Created" or current_user.is_authenticated and (current_user.username == listing.merchant or current_user.username == listing.client):
        return render_template("/listing.html", listing=vars(listing))
    else:
        flash("Listing is no longer public")
        return redirect(url_for("index"))

@app.route('/listing/')
def listing():
    return redirect(url_for("index"))

@app.route('/ban', methods=["POST"])
@login_required
def ban():
    if current_user.username != "Admin":
        return Response(response="Unauthorized", status=401) # Return 401 Unauthorized if user is not admin

    valid = True

    username_input = str(request.form.get("username") or "")
    ban_time = str(request.form.get("ban_time") or "")
    ban_reason = str(request.form.get("ban_reason") or "")

    user = Users.query.filter(Users.username == username_input).first() # Get row from databse using username

    if not bool(user): # Check that user exists
        flash("User does not exist", 'ban')
        valid = False

    if len(ban_reason) > 250:
        flash("Ban reason must be less than 250 characters long", 'ban')
        valid = False
    
    if valid:
        if ban_time == "PERMANENT":
            user.ban_reason = ban_reason
            user.ban_timer = -1
            flash(username_input + " was permanently banned", 'ban')

            db.session.commit()
        else:
            try:
                ban_time = int(ban_time)

                if ban_time > 315360000:
                    raise Exception

                user.ban_reason = ban_reason
                user.ban_timer = int(time.time()) + ban_time
                
                db.session.commit()
                
                flash(username_input + " was temporarily banned for " + "{:0>8}".format(str(timedelta(seconds=(user.ban_timer - int(time.time()))))), 'ban')
            except Exception as e:
                flash(str(e))
                flash("Invalid ban duration", 'ban')
            
    return render_template("/account.html")

@app.route('/delete', methods=["POST"])
@login_required
def delete():
    id = str(request.form.get("listing") or "")

    listing = Listings.query.filter(Listings.id == id).first()

    if not bool(listing):
        flash("Listing does not exist")
        return redirect(url_for("index"))

    if listing.client != "" and current_user.username != "Admin":
        flash("You cannot delete a listing after a client has accepted the listing")
        return redirect(url_for("display_listing", title=id))
    
    if current_user.username == listing.merchant or current_user.username == "Admin":
        if listing.listing_type == "Buy":
            user = Users.query.filter_by(username=listing.merchant).first()
            user.balance = user.balance + listing.price
        
        Listings.query.filter(Listings.id == id).delete()
        db.session.commit()

        flash("Listing " + id + " deleted successfully")

        return redirect(url_for("index"))
    else:
        flash("You cannot delete another user's listing")
        return redirect(url_for("display_listing", title=id))

@app.route('/create', methods=["GET", "POST"])
@login_required
def create():
    if request.method == "GET":
        return render_template("/create.html")
    else:
        valid = True
        
        listing_type = str(request.form.get("listing_type") or "")
        title = str(request.form.get("title") or "")
        description = str(request.form.get("description") or "")
        price_input = str(request.form.get("price") or "")
        contact = str(request.form.get("contact") or "")

        if current_user.ban_timer == -1: # Check if user is perma banned
            flash("You have been permanently banned for: " + current_user.ban_reason)
            flash("Banned accounts cannot create listings")
            return render_template("/create.html")

        if current_user.ban_timer > time.time(): # Check if user is still temp banned
            flash("You have been temporarily banned for: " + current_user.ban_reason)
            flash("Banned accounts cannot create listings")
            flash("You will be unbanned in " + "{:0>8}".format(str(timedelta(seconds=(current_user.ban_timer - int(time.time()))))))
            return render_template("/create.html")

        if listing_type not in ["Buy", "Sell"]:
            valid = False
            flash("Invalid listing type")

        if len(title) > 250 or len(title) < 5:
            valid = False
            flash("Title must be between 5 and 250 characters long")

        if len(description) > 2500 or len(description) < 5:
            valid = False
            flash("Description must be between 5 and 2500 characters long")

        if len(contact) > 250 or len(contact) < 5:
            valid = False
            flash("Contact must be between 5 and 250 characters long")

        try:
            price = decimal.Decimal(roundDown(price_input))

            if price < 0.01:
                raise Exception
        except Exception as e:
            flash("Invalid price")
            valid = False

        if valid and current_user.balance - price < 0 and listing_type == "Buy":
            valid = False
            flash("Insufficient balance")

        if valid:
            try:
                listing = Listings(id=str(uuid.uuid4()), status="Created", listing_type=listing_type, title=title, description=description, merchant=current_user.username, price=price, contact=contact)

                if listing_type == "Buy":
                    current_user.balance = current_user.balance - price

                db.session.add(listing)
                db.session.commit()

                flash("Listing created successfully")
                return redirect(url_for("index"))
            except Exception as e:
                db.session.rollback()
                flash("Sorry, something went wrong. Please try again later")
        
        return render_template("/create.html")

@app.route('/withdraw', methods=["POST"]) # Withdraw Banano
@login_required
def withdraw():
    amount_input = str(request.form.get("amount") or "")

    valid = True
    
    try:
        withdraw_amount = roundDown(amount_input) # Round to 2dp

        if withdraw_amount < 0.01 or withdraw_amount > current_user.balance: # Prevent zero or negative withdrawals
            assert Exception
    except:
        flash("Invalid amount", 'withdraw')
        valid = False

    if valid:
        try:
            banano_account.send(current_user.address, str(withdraw_amount)) # Send banano to user's Banano account
            
            current_user.balance = current_user.balance - decimal.Decimal(withdraw_amount) # Remove withdrawn Banano from user account
            
            db.session.commit()

            flash(f"Successfully withdrew {withdraw_amount} BAN to {current_user.address}", 'withdraw')
        except Exception as e:
            db.session.rollback()
            flash("Sorry, something went wrong. Please try again later", 'withdraw')
        
    return redirect(url_for("account"))

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "GET":
        return render_template("/signin.html")
    else:
        # Get inputs from login form
        username_input = str(request.form.get("username") or "") # Convert None to ""
        password_input = str(request.form.get("password") or "")
        
        user = Users.query.filter(Users.username == username_input).first() # Get row from databse using username

        if not bool(user):
            flash("Account does not exist")
            return render_template("/signin.html")

        try:
            ph.verify(user.password, password_input) # Check password against hash
            login_user(user) # Log in user if password matches hash

            if ph.check_needs_rehash(user.password): # Re-hash password if needed
                user.password = ph.hash(password_input)
                db.session.commit()

            return redirect(url_for("index"))
        except VerifyMismatchError: # Unless password does not match
            flash("Wrong Password")
            return render_template("/signin.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("/signup.html")
    else:
        email = str(request.form.get("email") or "") # Get form inputs
        password = str(request.form.get("password") or "")
        repeat_password = str(request.form.get("repeat") or "")
        username = str(request.form.get("username") or "")
        address = str(request.form.get("address") or "")

        # Validate inputs
        valid = True

        if len(email) > 50 or not re.match(r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", email): # Check if email is valid
            flash("Invalid email")
            valid = False

        if len(username) > 50 or len(username) < 1: # Check if there is a username
            flash("Invalid username")
            valid = False

        if not re.match(r"ban_[13][13456789abcdefghijkmnopqrstuwxyz]{59}\b", address): # Check if banano address is valid
            flash("Invalid address")
            valid = False

        if password != repeat_password: # First check if passwords match
            flash("Passwords do not match")
            valid = False
        elif len(password) > 50 or not re.match(r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*[^\w\d\s]).{8,}$", password): # Then check if password is secure (this way you only get 1 password error)
            flash("Password must be 8-50 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")
            valid = False

        if valid:
            try: # Add account to database
                user = Users(email=email, username=username, password=ph.hash(password), balance=0, address=address) # Create user object

                db.session.add(user) # Add user object to database
                db.session.commit()

                flash("Account created successfully")
                return redirect(url_for("signin"))
            except IntegrityError as e: # Unless email, address, or username already exist in database
                db.session.rollback()
                flash("Email, address, or username already in use")
                return render_template("/signup.html")
        else:
            return render_template("/signup.html")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8001, debug=True)
