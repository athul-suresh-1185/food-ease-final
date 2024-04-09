from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from os import path
from datetime import datetime
import jwt
from functools import wraps

# Database setup
db = SQLAlchemy()
bcrypt = Bcrypt()

# Authentication decorator
def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return func(current_user, *args, **kwargs)

    return decorated

# Flask app initialization
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'some random string'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    db.init_app(app)
    bcrypt.init_app(app)

    # Create database if it doesn't exist
    with app.app_context():
        if not path.exists('website/database.db'):
            db.create_all()
            print('Create Database!')

    @app.route('/test',methods=['GET'])
    def test():
        print('Something')

    @app.route('/user-login', methods=['POST'])
    def login():
        data = request.get_json()

    # Check if username and password are provided
        if 'user_name' not in data or 'password' not in data:
            return jsonify({'message': 'Username and password are required'}), 400

        user = User.query.filter_by(user_name=data['user_name']).first()

        if not user:
            return jsonify({'message': 'User not found'}), 401

    # Verify the password
        if not bcrypt.check_password_hash(user.password, data['password']):
            return jsonify({'message': 'Incorrect password'}), 401

    # If the user is verified, generate a JWT token
        token = jwt.encode({'user_id': user.user_id}, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'token': token}), 200


    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
    # Ensure 'wallet' is provided and not None
        if 'wallet' not in data or data['wallet'] is None:
            return jsonify({'message': 'Wallet field is required'}), 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(user_name=data['user_name'], password=hashed_password, wallet=data['wallet'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201


    @app.route('/user_details', methods=['GET'])
    @token_required
    def user_details(current_user):
        user_details = {
            'user_name': current_user.user_name,
            'wallet_balance': current_user.wallet
        }
        return jsonify({'user_details': user_details})

    @app.route('/daily_menu', methods=['GET'])
    @token_required
    def daily_menu(current_user):
        food_details = []
        daily_menu_items = DailyMenu.query.all()
        for daily_menu in daily_menu_items:
            food = Food.query.get(daily_menu.food_id)
            food_dict = {
                'food_id': daily_menu.food_id,
                'item_name': food.item_name,
                'bought_count': food.bought_count,
                'price': food.price
            }
            food_details.append(food_dict)
        return jsonify({'daily_menu': food_details})

    @app.route('/place_order', methods=['POST'])
    @token_required
    def place_order(current_user):
        # Get data from the request
        order_data = request.json
        order_items = order_data.get('items', [])

        # Calculate total amount based on order items
        total_amount = sum(item['quantity'] * item['total_price'] for item in order_items)

        # Increment the order token value
        last_order = Order.query.order_by(Order.order_id.desc()).first()
        token_value = 1 if last_order is None else last_order.token + 1

        # Check if wallet balance is sufficient
        if current_user.wallet < total_amount:
            return jsonify({'message': 'Insufficient balance'}), 400

        # Deduct total amount from wallet balance
        current_user.wallet -= total_amount

        # Create OrderItem instances and add them to the list of order items
        order_items_instances = []
        for item in order_items:
            food_id = item.get('food_id')
            quantity = item.get('quantity', 1) # Default to 1 if quantity is not provided

            # Retrieve food details
            food = Food.query.get(food_id)
            if not food:
                return jsonify({'message': 'Food item not found'}), 404

            # Update bought count in Food table
            food.bought_count += quantity

            # Create an OrderItem and add it to the list of order items
            order_item = OrderItem(food_id=food_id, quantity=quantity, total_price=item['total_price'])
            order_items_instances.append(order_item)

        # Create the order
        order = Order(user_id=current_user.user_id, token=token_value, status='Delivered', total_amount=total_amount, items=order_items_instances)
        db.session.add(order)

        try:
            # Commit the changes to the database
            db.session.commit()
            # Return the token and order details with status "Delivered"
            return jsonify({'order_token': order.token, 'order_details': order_items, 'status': 'Delivered'}), 200
        except:
            # Rollback changes if an error occurs
            db.session.rollback()
            return jsonify({'message': 'Failed to place order. Please try again later.'}), 500

    @app.route('/order_history', methods=['GET'])
    @token_required
    def get_combined_order_history(current_user):
        try:
            # Query for current orders ('Ordered' or 'Pinged')
            current_orders_subquery = db.session.query(
                Order.order_id, Order.order_date, Order.total_amount, Order.status,
                Order.token, # Include the token in the query
                db.literal_column("'Current'").label('order_type')
            ).filter(
                Order.user_id == current_user.user_id,
                Order.status.in_(['Ordered', 'Pinged'])
            ).subquery()

            # Query for past orders ('Delivered'), limiting to the last 5
            past_orders_subquery = db.session.query(
                Order.order_id, Order.order_date, Order.total_amount, Order.status,
                Order.token, # Include the token in the query
                db.literal_column("'Past'").label('order_type')
            ).filter(
                Order.user_id == current_user.user_id,
                Order.status == 'Delivered'
            ).order_by(
                Order.order_date.desc()
            ).limit(5).subquery()

            # Combine the results of both subqueries
            combined_orders = db.session.query(
                current_orders_subquery.c.order_id,
                current_orders_subquery.c.order_date,
                current_orders_subquery.c.total_amount,
                current_orders_subquery.c.status,
                current_orders_subquery.c.token, # Include the token in the combined query
                current_orders_subquery.c.order_type
            ).union_all(
                db.session.query(
                    past_orders_subquery.c.order_id,
                    past_orders_subquery.c.order_date,
                    past_orders_subquery.c.total_amount,
                    past_orders_subquery.c.status,
                    past_orders_subquery.c.token, # Include the token in the combined query
                    past_orders_subquery.c.order_type
                )
            ).all()

            # Serialize order data into JSON format
            order_history = []
            for order in combined_orders:
                order_data = {
                    'order_id': order.order_id,
                    'order_date': order.order_date.strftime('%Y-%m-%d %H:%M:%S'), # Convert datetime to string
                    'total_amount': order.total_amount,
                    'status': order.status,
                    'order_type': order.order_type,
                    'token': order.token # Include the token in the response
                }
                order_history.append(order_data)

            # Return the combined order history as a JSON response including the token
            return jsonify({'order_history': order_history}), 200
        except Exception as e:
            return jsonify({'message': 'Failed to fetch combined order history. Please try again later.', 'error': str(e)}), 500

    return app

# Database models
# Database models
class Admin(db.Model):
    __tablename__ = 'admin'
    admin_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    wallet = db.Column(db.Float, nullable=False)

class Food(db.Model):
    __tablename__ = 'food'
    food_id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    bought_count = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class MonthlyMenu(db.Model):
    __tablename__ = 'monthly_menu'
    food_id = db.Column(db.Integer, db.ForeignKey('food.food_id'), primary_key=True)
    food = db.relationship('Food', backref=db.backref('monthly_menu', lazy=True))

class DailyMenu(db.Model):
    __tablename__ = 'daily_menu'
    food_id = db.Column(db.Integer, db.ForeignKey('food.food_id'), primary_key=True)
    food = db.relationship('Food', backref=db.backref('daily_menu', lazy=True))

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.order_id'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.food_id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

class Order(db.Model):
    __tablename__ = 'orders'
    order_id = db.Column(db.Integer, primary_key=True)
    order_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    token = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    items = db.relationship('OrderItem', backref='order', lazy=True)
    status = db.Column(db.String(50), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)


app = create_app()

if __name__ == '__main__':
  app.run(debug=True, port=5000)

