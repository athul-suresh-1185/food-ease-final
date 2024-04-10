from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy # type: ignore
from flask_bcrypt import Bcrypt
from os import path
from datetime import datetime
import jwt
import uuid
from functools import wraps
from flask_cors import CORS # type: ignore
import openai
import time
import random

def generate_order_token():
    # Combine the current timestamp with a random number
    return int(time.time()) + random.randint(1000, 9999)


openai.api_key = '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'

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

def admin_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        # Check if the user is an admin
        admin_user = Admin.query.filter_by(admin_id=current_user_id).first()
        if not admin_user:
            return jsonify({'message': 'Admin access required'}), 403

        return func(admin_user, *args, **kwargs)

    return decorated

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'some random string'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    db.init_app(app)
    bcrypt.init_app(app)
    CORS(app)

    # Create database if it doesn't exist
    with app.app_context():
        if not path.exists('database.db'):
            db.create_all()
            print('Create Database!')

    # User routes
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

    @app.route('/user_details', methods=['GET', 'OPTIONS'])
    @token_required
    def user_details(current_user):
        if request.method == 'OPTIONS':
            user_details = {
                'user_name': current_user.user_name,
                'wallet_balance': current_user.wallet
        }
        return jsonify({'user_details': user_details})

    @app.route('/user/daily_menu', methods=['GET'])
    @token_required
    def daily_menu(current_user):
        food_details = []
        daily_menu_items = DailyMenu.query.all()
        for daily_menu in daily_menu_items:
            food = Food.query.get(daily_menu.food_id)
            food_dict = {
                'food_id': daily_menu.food_id,
                'item_name': food.item_name,
                'price': food.price
                }
            food_details.append(food_dict)
        return jsonify({'daily_menu': food_details})
    
    @app.route('/place_order', methods=['POST'])
    @token_required
    def place_order(current_user):
        order_data = request.json
        order_items = order_data.get('items', [])

        total_amount = 0
        order_items_instances = []

        for item in order_items:
            food_id = item.get('food_id')
            quantity = item.get('quantity', 1)
            food = Food.query.get(food_id)
            if not food:
                return jsonify({'message': 'Food item not found'}), 404

            total_price = food.price * quantity
            total_amount += total_price

            food.bought_count += quantity

            order_item = OrderItem(food_id=food_id, quantity=quantity, total_price=total_price)
            order_items_instances.append(order_item)

    # Generate a unique token for the order
        token_value = generate_order_token()

    # Create the order
        order = Order(user_id=current_user.user_id, token=token_value, status='Delivered', total_amount=total_amount, items=order_items_instances, is_past_order=True)
        db.session.add(order)

        try:
            db.session.commit()
            return jsonify({'order_token': order.token, 'order_details': order_items, 'status': 'Ordered'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Failed to place order. Please try again later.', 'error': str(e)}), 500
        

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

    # Reception routes
    @app.route('/reception/orders', methods=['GET'])
    @admin_required
    def get_reception_orders(admin_user):
        try:
            # Query for orders with status 'Ordered' or 'Pinged'
            orders = Order.query.join(OrderItem).filter(
                Order.status.in_(['Ordered', 'Pinged'])
            ).all()

            # Serialize order data into JSON format
            order_details = []
            for order in orders:
                order_items = []
                for item in order.items:
                    food = Food.query.get(item.food_id)
                    order_items.append({
                        'food_name': food.item_name,
                        'food_quantity': item.quantity
                    })

                order_data = {
                    'order_id': order.order_id,
                    'token_no': order.token,
                    'items': order_items,
                    'status': order.status,
                    'total_price': order.total_amount
                }
                order_details.append(order_data)

            return jsonify({'orders': order_details}), 200
        except Exception as e:
            return jsonify({'message': 'Failed to fetch orders. Please try again later.', 'error': str(e)}), 500

    # Admin routes
    @app.route('/admin/register', methods=['POST'])
    def admin_register():
        data = request.json
        username = data.get('user_name')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        # Check if the admin already exists
        existing_admin = Admin.query.filter_by(user_name=username).first()
        if existing_admin:
            return jsonify({'message': 'Admin with this username already exists'}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new admin
        new_admin = Admin(user_name=username, password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()

        return jsonify({'message': 'Admin created successfully'}), 201
    
    @app.route('/admin/login', methods=['POST'])
    def admin_login():
        data = request.get_json()
        username = data.get('user_name')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        admin = Admin.query.filter_by(user_name=username).first()
        if not admin or not bcrypt.check_password_hash(admin.password, password):
            return jsonify({'message': 'Invalid credentials'}), 401

        # Generate a JWT token
        token = jwt.encode({'user_id': admin.admin_id}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token}), 200
    

    # User routes
    @app.route('/admin/add_food', methods=['POST'])
    @admin_required
    def add_food(admin_user):
        data = request.get_json()
        
        # Check if the required fields are provided
        if 'item_name' not in data or 'bought_count' not in data or 'price' not in data:
            return jsonify({'message': 'Item name, bought count, and price are required'}), 400
        
        # Create a new food item
        new_food = Food(
            item_name=data['item_name'],
            bought_count=data['bought_count'],
            price=data['price']
        )
        
        try:
            db.session.add(new_food)
            db.session.commit()
            return jsonify({'message': 'Food item added successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Failed to add food item', 'error': str(e)}), 500
   

    @app.route('/admin/get_users', methods=['POST'])
    @admin_required
    def get_all_users(admin_user):
        try:
            # Retrieve all users from the User table
            all_users = User.query.all()

            # Serialize the user data
            users = []
            for user in all_users:
                user_dict = {
                    'user_id': user.user_id,
                    'user_name': user.user_name,
                    'wallet': user.wallet
                }
                users.append(user_dict)

            return jsonify({'users': users}), 200
        except Exception as e:
            return jsonify({'message': 'Failed to retrieve users', 'error': str(e)}), 500
        
    @app.route('/admin/set_daily_menu', methods=['POST'])
    @admin_required
    def set_daily_menu(admin_user):
        data = request.get_json()
        
        # Check if the required fields are provided
        if 'food_ids' not in data:
            return jsonify({'message': 'Food IDs are required'}), 400
        
        # Delete existing daily menu items
        DailyMenu.query.delete()
        
        # Create new daily menu items
        for food_id in data['food_ids']:
            daily_menu_item = DailyMenu(food_id=food_id)
            db.session.add(daily_menu_item)
        
        try:
            db.session.commit()
            return jsonify({'message': 'Daily menu updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Failed to update daily menu', 'error': str(e)}), 500
        
    @app.route('/admin/get_foods', methods=['POST'])
    @admin_required
    def get_all_foods(admin_user):
        try:
            # Retrieve all food items from the Food table
            all_foods = Food.query.all()

            # Serialize the food item data
            foods = []
            for food in all_foods:
                food_dict = {
                    'food_id': food.food_id,
                    'item_name': food.item_name,
                    'bought_count': food.bought_count,
                    'price': food.price
                }
                foods.append(food_dict)

            return jsonify({'foods': foods}), 200
        except Exception as e:
            return jsonify({'message': 'Failed to retrieve food items', 'error': str(e)}), 500

    @app.route('/admin/get_daily_menu', methods=['POST'])
    @admin_required
    def get_daily_menu(admin_user):
        try:
            # Retrieve all items from the DailyMenu table
            all_daily_menu_items = DailyMenu.query.all()

            # Serialize the daily menu item data
            daily_menu = []
            for daily_menu_item in all_daily_menu_items:
                food = Food.query.get(daily_menu_item.food_id)
                daily_menu_dict = {
                    'food_id': daily_menu_item.food_id,
                    'item_name': food.item_name,
                    'price': food.price
                }
                daily_menu.append(daily_menu_dict)

            return jsonify({'daily_menu': daily_menu}), 200
        except Exception as e:
            return jsonify({'message': 'Failed to retrieve daily menu items', 'error': str(e)}), 500  
        

    @app.route('/admin/get_orders', methods=['POST'])
    @admin_required
    def get_all_orders(admin_user):
        try:
            # Retrieve all orders from the Order table
            all_orders = Order.query.all()

            # Serialize the order data
            orders = []
            for order in all_orders:
                order_dict = {
                    'order_id': order.order_id,
                    'order_date': order.order_date.strftime('%Y-%m-%d %H:%M:%S'),
                    'token': order.token,
                    'user_id': order.user_id,
                    'status': order.status,
                    'total_amount': order.total_amount
                }
                orders.append(order_dict)

            return jsonify({'orders': orders}), 200
        except Exception as e:
            return jsonify({'message': 'Failed to retrieve orders', 'error': str(e)}), 500
              
    
    
    @app.route('/admin/food_items', methods=['GET'])
    @admin_required
    def get_all_food_items(admin_user):
        try:
            # Retrieve all food items from the Food table
            all_food_items = Food.query.all()

            # Serialize the food item data
            food_items = []
            for food_item in all_food_items:
                food_dict = {
                    'food_id': food_item.food_id,
                    'item_name': food_item.item_name,
                    'bought_count': food_item.bought_count,
                    'price': food_item.price
                }
                food_items.append(food_dict)

            return jsonify({'food_items': food_items}), 200
        except Exception as e:
            return jsonify({'message': 'Failed to retrieve food items', 'error': str(e)}), 500

    return app



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
    is_past_order = db.Column(db.Boolean, default=False)


app = create_app()

if __name__ == '__main__':
    app.run(debug=True)