from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime
import stripe
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask import Flask, flash
from flask import request, redirect, flash
from bson.objectid import ObjectId


from functools import wraps
from flask import session, redirect, url_for, flash




app = Flask(__name__)
app.secret_key = "your_secret_key"
CORS(app) 

stripe.api_key = "sk_test_51R1netCK0Y9VqYX7A0faQh1IRzGPLyrx4gneXcR1mVjhWNVoILVV0rW8N0oWox5RTRQeayAk82cLjXWQptrbktmh003CGp2rrl"


# Define the admin_required decorator before using it
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Unauthorized access"}), 401
        return f(*args, **kwargs)
    return decorated_function



# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["WATER"]  # Ensure this matches your database name

# Assign users collection
users = db["users"]
consumption = db["consumption"]
comments = db["comments"]
issues = db["issues"]
payment = db["payment"]
bills = db["bills"] 

# Configure MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/WATER"
mongo = PyMongo(app)


@app.route("/")
def home():
    return render_template("index.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form

        # Extract user details
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        role = data.get("role", "").strip()

        # Validate input fields
        if not username or not password or not role:
            return jsonify({"success": False, "message": "All fields are required!"})

        # Check if username already exists
        if users.find_one({"username": username}):
            return jsonify({"success": False, "message": "Username already exists!"})

        # Hash the password before storing
        hashed_password = generate_password_hash(password)

        # Store user in the database
        users.insert_one({"username": username, "password": hashed_password, "role": role})

        return jsonify({"success": True, "redirect": "/login"})  # Redirect to login page

    return render_template("register.html")






@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 🔹 Support both form-data & JSON requests
        if request.is_json:
            data = request.get_json()
            username = data.get("username")
            password = data.get("password")
        else:
            username = request.form.get("username")
            password = request.form.get("password")

        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        user = users.find_one({"username": username})

        if user and check_password_hash(user["password"], password):
            session["user_id"] = str(user["_id"])
            session["username"] = user["username"]
            session["role"] = user["role"]

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user["role"] == "customer":
                return redirect(url_for("customer_dashboard"))
            else:
                return jsonify({"error": "Unauthorized Role"}), 403
        else:
            return jsonify({"error": "Invalid Credentials"}), 401

    return render_template("login.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    # Fetch all payments from MongoDB
    payments = list(mongo.db.payment.find())

    return render_template("admin_dashboard.html", user=session, payments=payments)





@app.route('/add_customer', methods=['POST'])
def add_customer():
    data = request.json
    full_name = data.get('fullName')
    username = data.get('username')
    password = data.get('password')
    
    if not full_name or not username or not password:
        return jsonify({"message": "All fields are required."}), 400
    
    # Check if username already exists
    existing_user =users.find_one({"username": username})
    if existing_user:
        return jsonify({"message": "Username already exists."}), 400
    
    # Insert new customer into the database
    user_id =users.insert_one({
        "full_name": full_name,
        "username": username,
        "password": password  # Store hashed password in production
    }).inserted_id
    
    return jsonify({"message": "Customer added successfully!", "user_id": str(user_id)}), 201


@app.route("/customer_dashboard")
def customer_dashboard():
    if "user_id" not in session or session.get("role") != "customer":
        return redirect(url_for("login"))

    comments = list(mongo.db.comments.find().sort("timestamp", -1))  # Fetch all comments (latest first)

    return render_template("customer_dashboard.html", user=session, comments=comments)





@app.route("/check_admin")
def check_admin():
    if "username" in session and session["role"] == "admin":
        return jsonify({"is_admin": True})
    return jsonify({"is_admin": False})




@app.route("/submit_comment", methods=["POST"])
def submit_comment():
    if "user_id" not in session or session.get("role") != "customer":
        return redirect(url_for("login"))

    comment_text = request.form.get("comment")

    if not comment_text:
        flash("Comment cannot be empty.", "error")
        return redirect(url_for("customer_dashboard"))

    # Insert the comment into MongoDB (comments collection)
    comment_data = {
        "user_id": session["user_id"],
        "username": session.get("username"),  # Optional: Store the username
        "comment": comment_text,
        "timestamp": datetime.datetime.utcnow()  # Store timestamp
    }
    mongo.db.comments.insert_one(comment_data)

    flash("Comment submitted successfully!", "success")
    return redirect(url_for("customer_dashboard"))



# Admin can view and update feedback
@app.route("/admin/feedback", methods=["GET", "POST"])
def admin_feedback():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))
    
    feedbacks = list(mongo.db.feedback.find())

    if request.method == "POST":
        feedback_id = request.form.get("feedback_id")
        updated_status = request.form.get("status")
        mongo.db.feedback.update_one({"_id": ObjectId(feedback_id)}, {"$set": {"status": updated_status}})
        flash("Feedback updated!", "success")
        return redirect(url_for("admin_feedback"))

    return render_template("admin_feedback.html", feedbacks=feedbacks)



@app.route('/report', methods=['POST'])
def report_issue():
    if request.method == 'POST':
        issue_description = request.form.get('issue_description')
        username = session.get('username')

        if issue_description and username:
            issue_data = {
                'username': username,
                'issue': issue_description,
                'status': 'Pending',
                'timestamp': datetime.datetime.utcnow()

            }
            mongo.db.issues.insert_one(issue_data)  
            flash("Issue reported successfully!", "success")  # ✅ Flash success message
        else:
            flash("Failed to report issue. Please try again.", "error")  # ✅ Flash error message

    return redirect(url_for('customer_dashboard'))


# Admin can view and update issues
@app.route("/admin/issues", methods=["GET", "POST"])
def admin_issues():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))
    
    issues = list(mongo.db.issues.find())

    if request.method == "POST":
        issue_id = request.form.get("issue_id")
        updated_status = request.form.get("status")
        mongo.db.issues.update_one({"_id": ObjectId(issue_id)}, {"$set": {"status": updated_status}})
        flash("Issue updated!", "success")
        return redirect(url_for("admin_issues"))

    return render_template("admin_issues.html", issues=issues)



@app.route('/update_consumption', methods=['POST'])
def update_consumption():
    data = request.json
    print("Received data:", data)
    user_id = data.get("user_id")
    username = data.get("username")  # Get username
    billing_month = data.get("billing_month")
    daily_consumption = data.get("daily_consumption")
    print(user_id)

    if not user_id or not username or not billing_month or not daily_consumption:
        return jsonify({"error": "Missing fields"}), 400

    try:
        user_id = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400

    # ✅ Update or insert consumption record with username
    db.consumption.update_one(
        {"user_id": user_id, "billing_month": billing_month},
        {"$set": {"username": username, "daily_consumption": daily_consumption}},
        upsert=True
    )

    return jsonify({"success": True})


@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if request.method == 'POST':
        # Get payment details from form
        username = request.form.get('username')
        amount = request.form.get('amount')

        # Debug: Print received data
        print(f"Received -> Username: {username}, Amount: {amount}")

        if not username or not amount:
            return jsonify({"message": "Username and Amount are required!"}), 400

        try:
            amount = float(amount)
        except ValueError:
            return jsonify({"message": "Invalid amount format!"}), 400

        # Save payment in MongoDB
        payment_record = {
    "username": username,
    "amount": amount,
    "date": datetime.utcnow()  # ✅ This will now work correctly
}


        result = payment.insert_one(payment_record)

        if result.inserted_id:
            print("✅ Payment stored successfully")

            # Update bill in `bills` collection
            bills.update_one(
                {"username": username},
                {"$inc": {"total_paid": amount}, "$set": {"last_payment_date": datetime.utcnow()}},
                upsert=True  # Create if it doesn't exist
            )

            print("✅ Bill updated successfully")
            return redirect(url_for('payment_invoice', amount=amount, username=username))

        return jsonify({"message": "Failed to store payment!"}), 500

    return render_template('payment.html')  # Ensure 'payment.html' exists






# After successful payment, redirect to invoice page
@app.route("/payment-success", methods=["GET"])
def payment_success():
    try:
        payment_intent_id = request.args.get("payment_intent")

        if not payment_intent_id:
            return jsonify({"error": "Payment intent ID is required"}), 400

        # Retrieve payment details from MongoDB
        payment = mongo.db.payment.find_one({"payment_intent_id": payment_intent_id})

        if not payment:
            return jsonify({"error": "Payment not found"}), 404

        # Update payment status to "successful"
        mongo.db.payment.update_one(
            {"payment_intent_id": payment_intent_id},
            {"$set": {"status": "successful"}}
        )

        # Redirect to invoice page (modify as per your frontend URL)
        return redirect(f"/invoice?payment_intent={payment_intent_id}")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


stripe.api_key = "sk_test_51R1netCK0Y9VqYX7A0faQh1IRzGPLyrx4gneXcR1mVjhWNVoILVV0rW8N0oWox5RTRQeayAk82cLjXWQptrbktmh003CGp2rrl"


@app.route("/create-payment-intent", methods=["POST"])
def create_payment():
    try:
        data = request.json
        amount = data.get("amount")
        user_id = session.get("user_id") or data.get("user_id")  # Get user ID

        if not amount or not user_id:
            return jsonify({"error": "User ID and Amount are required"}), 400

        # ✅ Convert amount to cents (Stripe requires cents)
        try:
            amount_cents = int(float(amount) * 100)
        except ValueError:
            return jsonify({"error": "Invalid amount format"}), 400

        # ✅ Create PaymentIntent with Stripe
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency="usd",
            payment_method_types=["card"]
        )

        # ✅ Convert user_id if stored as ObjectId in MongoDB
        try:
            user_id = ObjectId(user_id)
        except Exception:
            return jsonify({"error": "Invalid user ID format"}), 400

        # ✅ Save payment record in MongoDB
        payment_record = {
            "user_id": user_id,
            "amount": float(amount),  # Store in dollars
            "status": "successful",  # Payment is not completed yet
            "payment_intent_id": intent.id,  # Store PaymentIntent ID
            "date": datetime.utcnow()
        }

        result = db.payment.insert_one(payment_record)  # Store in 'payment' collection

        print(f"Inserted payment with ID: {result.inserted_id}")  # Debugging

        return jsonify({"clientSecret": intent.client_secret})

    except Exception as e:
        print(f"Error: {e}")  # Debugging
        return jsonify({"error": str(e)}), 500





@app.route("/api/get-invoice", methods=["GET"])
def get_invoice():
    try:
        payment_intent_id = request.args.get("payment_intent")

        if not payment_intent_id:
            return jsonify({"error": "Payment intent ID is required"}), 400

        payment = mongo.db.payments.find_one({"payment_intent_id": payment_intent_id})

        if not payment:
            return jsonify({"error": "Invoice not found"}), 404

        return jsonify({
            "amount": payment["amount"],
            "currency": payment["currency"],
            "status": payment["status"],
            "date": payment["date"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# Optional: Webhook for receiving asynchronous events from Stripe
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")
    endpoint_secret = "YOUR_WEBHOOK_SECRET"

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except stripe.error.SignatureVerificationError:
        return "Signature verification failed", 400

    # Extract payment intent data
    payment_intent = event["data"]["object"]
    payment_id = payment_intent["id"]
    amount_received = payment_intent["amount_received"] / 100  # Convert from cents
    currency = payment_intent["currency"].upper()
    status = payment_intent["status"]

    # Connect to MongoDB
    mongo_client = pymongo.MongoClient("YOUR_MONGO_URI")
    db = mongo_client["safi_water_billing"]
    payment_collection = db["payment"]
    bills_collection = db["bills"]

    if event["type"] == "payment_intent.succeeded":
        print(f"✅ Payment succeeded: {payment_id}")

        # Update the payment record
        payment_collection.update_one(
            {"payment_intent_id": payment_id},
            {"$set": {"status": "succeeded"}}
        )

        # Update the corresponding bill in the billing system
        bills_collection.update_one(
            {"payment_intent_id": payment_id},
            {"$set": {"status": "paid"}}
        )

    elif event["type"] == "payment_intent.payment_failed":
        print(f"❌ Payment failed: {payment_id}")

        # Update the payment record
        payment_collection.update_one(
            {"payment_intent_id": payment_id},
            {"$set": {"status": "failed"}}
        )

    else:
        # For pending or other statuses, store the payment if it doesn’t exist
        existing_payment = payment_collection.find_one({"payment_intent_id": payment_id})
        if not existing_payment:
            print(f"⏳ Storing pending payment: {payment_id}")

            payment_collection.insert_one({
                "payment_intent_id": payment_id,
                "amount": amount_received,
                "currency": currency,
                "status": status,
                "date": datetime.utcnow()
            })

            # Also update or store the bill as pending
            bills_collection.update_one(
                {"payment_intent_id": payment_id},
                {
                    "$set": {
                        "status": "pending",
                        "amount_due": amount_received,
                        "currency": currency
                    }
                },
                upsert=True
            )

    return "OK", 200


# Admin can approve payments
@app.route("/admin/payment", methods=["GET", "POST"])
def admin_payments():
    if "username" not in session or session["role"] != "admin":
        return redirect(url_for("login"))
    
    payments = list(mongo.db.payments.find())

    if request.method == "POST":
        payment_id = request.form.get("payment_id")
        updated_status = request.form.get("status")
        mongo.db.payments.update_one({"_id": ObjectId(payment_id)}, {"$set": {"status": updated_status}})
        flash("Payment updated!", "success")
        return redirect(url_for("admin_payments"))

    return render_template("admin_payments.html", payments=payments)


@app.route("/admin/approve-payment", methods=["POST"])
def approve_payments():
    try:
        data = request.get_json()
        payment_intent_id = data.get("payment_intent_id")

        if not payment_intent_id:
            return jsonify({"error": "Payment Intent ID is required"}), 400

        # Find the payment record in MongoDB
        payment = mongo.db.payments.find_one({"payment_intent_id": payment_intent_id})

        if not payment:
            return jsonify({"error": "Payment not found"}), 404

        if payment["status"] != "pending":
            return jsonify({"error": "Payment is already processed"}), 400

        # Update payment status to approved
        mongo.db.payments.update_one(
            {"payment_intent_id": payment_intent_id},
            {"$set": {"status": "approved"}}
        )

        return jsonify({"message": "Payment approved successfully!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


from flask import render_template
from pymongo import MongoClient

@app.route('/billing')
def billing():
    consumptions = list(db.consumption.find({}, {"user_id": 1, "daily_consumption": 1}))
    payments = list(db.payment.find({}, {"user_id": 1, "amount": 1}))

    billing_data = {}

    # Process consumption data
    for consumption in consumptions:
        user_id = consumption.get("user_id")  # Use 'user_id' from the DB
        if not user_id:
            print("ERROR: Consumption record missing user_id:", consumption)
            continue  

        water_used = float(consumption.get("daily_consumption", 0))  # Convert to float
        bill_amount = water_used * 50  # Adjust your billing rate

        billing_data[user_id] = {
            "user_id": user_id,
            "water_used": water_used,
            "bill_amount": bill_amount,
            "amount_paid": 0,
            "balance": bill_amount
        }

    # Process payments
    for payment in payments:
        user_id = payment.get("user_id")  # Match 'user_id' from payments
        if not user_id:
            print("ERROR: Payment record missing user_id:", payment)
            continue  

        amount_paid = float(payment.get("amount", 0))  # Convert to float
        if user_id in billing_data:
            billing_data[user_id]["amount_paid"] += amount_paid
            billing_data[user_id]["balance"] = max(0, billing_data[user_id]["bill_amount"] - billing_data[user_id]["amount_paid"])

    billing_list = list(billing_data.values())

    return render_template('billing.html', billing=billing_list)





@app.route("/api/generate_bills", methods=["POST"])
def generate_bills():
    data = request.json
    customer_id = data.get("customer_id")

    if not customer_id:
        return jsonify({"error": "Customer ID is required"}), 400

    # Fetch customer water consumption
    consumption = db.consumption.find_one({"customer_id": customer_id})
    if not consumption:
        return jsonify({"error": "No consumption record found"}), 404

    total_consumption = consumption.get("cubic_meters", 0)
    bill_amount = total_consumption * 50  # Adjust billing rate per cubic meter

    # Fetch previous payments
    payments = list(db.payment.find({"customer_id": customer_id}))
    total_paid = sum(payment.get("amount", 0) for payment in payments)
    balance = bill_amount - total_paid

    # Check if bill exists, update if needed
    existing_bill = db.consumption.find_one({"customer_id": customer_id})
    billing_month = datetime.now().strftime("%B %Y")
    due_date = datetime.now() + timedelta(days=30)

    bill_data = {
        "customer_id": customer_id,
        "total_amount": bill_amount,
        "total_consumption": total_consumption,
        "amount_paid": total_paid,
        "balance": balance,
        "billing_month": billing_month,
        "due_date": due_date.isoformat()
    }

    if existing_bill:
        db.consumption.update_one({"customer_id": customer_id}, {"$set": bill_data})
    else:
        db.consumption.insert_one(bill_data)

    return jsonify(bill_data)

@app.route("/api/fetch_bills", methods=["GET"])
def fetch_bills():
    bills = list(db.consumption.find({}, {"_id": 0}))  # Fetch all bills
    return jsonify(bills)



@app.route("/get_issues", methods=["GET"])
def get_issues():
    issues = list(db.issues.find({}, {"_id": 0, "username": 1, "issue": 1, "timestamp": 1}))
    return jsonify(issues)






@app.route('/logout')
def logout():
    session.clear()  # Clears user session
    return redirect(url_for('login')) 



@app.route("/get_comments", methods=["GET"])
def get_comments():
    comments = list(db.comments.find({}, {"_id": 0, "username": 1, "comment": 1, "timestamp": 1}))
    return jsonify(comments)


@app.route('/get_user_id', methods=['GET'])
def get_user_id():
    username = request.args.get("username")
    user = db.users.find_one({"username": username}, {"_id": 1})  # Change "users" to match your collection name
    if user:
        return jsonify({"user_id": str(user["_id"])})
    else:
        return jsonify({"error": "User not found"}), 404




@app.route('/get_consumption', methods=['GET'])
def get_consumption():
    user_id = session.get("user_id")  
    print("🔍 User ID from session:", user_id)  # Debugging

    if not user_id:
        return jsonify({"error": "User not logged in"}), 401  

    # Check if user_id is stored as an ObjectId in MongoDB
    try:
        user_id = ObjectId(user_id)  # Convert to ObjectId if needed
    except:
        pass  # If user_id is a string, continue normally

    # Fetch the consumption record
    consumption_record = db.consumption.find_one({"user_id": user_id}, {"_id": 0, "consumption": 1})
    print("🔍 Fetched from MongoDB:", consumption_record)  # Debugging

    if consumption_record:
        return jsonify(consumption_record)  
    else:
        return jsonify({"error": "No consumption data found"}), 404  
 
 

@app.route("/admin/update-consumption", methods=["POST"])
def update_water_consumption():
    data = request.json
    customer_id = data.get("customer_id")
    new_consumption = data.get("total_consumption")

    if not customer_id or new_consumption is None:
        return jsonify({"error": "Missing data"}), 400

    # Update the customer's water consumption
    db.consumption.update_one(
        {"customer_id": customer_id},
        {"$set": {"total_consumption": new_consumption, "last_updated": datetime.utcnow()}},
        upsert=True
    )

    return jsonify({"message": "Water consumption updated successfully"})






@app.route('/blog')
def blog():
    return render_template('blog.html')



if __name__ == "__main__":
    app.run(debug=True)
