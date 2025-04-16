from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import DecimalField, DateField,SelectField, StringField, PasswordField, SubmitField, EmailField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, NumberRange
from flask_session import Session
from functools import wraps
from decimal import Decimal
import pymysql
import random
import string

app = Flask(__name__)
app.secret_key = 'snus'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '159357Sulman2006?'
app.config['MYSQL_DB'] = 'banking_system'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

mysql = MySQL(app)
bcrypt = Bcrypt(app)
Session(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:  # ⬅️ Ако няма логнат потребител, пращаме към login
            flash('Моля, влезте в системата!', 'warning')
            return redirect(url_for('login'))

        if session.get('role') != 'admin':  
            flash('Нямате достъп до тази страница!', 'danger')
            return redirect(url_for('index'))  # ✅ Пренасочваме към началната страница

        return f(*args, **kwargs)
    return decorated_function


class RegisterForm(FlaskForm):
    username = StringField('Потребителско име', validators=[DataRequired(), Length(min=4, max=50)])
    email = EmailField('Имейл', validators=[DataRequired(), Email()])
    password = PasswordField('Парола', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Потвърдете паролата', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('Име', validators=[DataRequired()])
    last_name = StringField('Фамилия', validators=[DataRequired()])
    date_of_birth = DateField('Дата на раждане', format='%Y-%m-%d', validators=[DataRequired()])
    national_id = StringField('ЕГН', validators=[DataRequired(), Length(min=10, max=10)])
    phone_number = StringField('Телефонен номер', validators=[DataRequired(), Length(min=7, max=15)])
    address = TextAreaField('Адрес', validators=[DataRequired()])
    citizenship = StringField('Гражданство', validators=[DataRequired()])
    status = SelectField('Статус', choices=[('active', 'Активен'), ('inactive', 'Неактивен'), ('suspended', 'Спрян')], default='active')
    role = SelectField('Роля', choices=[('customer', 'Клиент'), ('admin', 'Администратор')], default='customer')
    submit = SubmitField('Регистрация')

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        date_of_birth = request.form['date_of_birth']
        national_id = request.form['national_id']
        phone_number = request.form['phone_number']
        address = request.form['address']
        citizenship = request.form['citizenship']
        status = request.form['status']
        role = request.form['role']

        # Хеширане на паролата
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Записване в базата данни
        cur = mysql.connection.cursor()
        try:
            cur.execute("""
                INSERT INTO users (username, password_hash, email, first_name, last_name, date_of_birth, national_id, phone_number, address, citizenship, status, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (username, password_hash, email, first_name, last_name, date_of_birth, national_id, phone_number, address, citizenship, status, role))
            mysql.connection.commit()
            flash('Потребителят е добавен успешно!', 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Грешка при добавяне: {str(e)}', 'danger')
        finally:
            cur.close()

        return redirect(url_for('admin_dashboard'))

    return render_template('add_user.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        date_of_birth = form.date_of_birth.data
        national_id = form.national_id.data
        phone_number = form.phone_number.data
        address = form.address.data
        citizenship = form.citizenship.data
        status = 'активен'
        role = 'потребител'

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        cur = mysql.connection.cursor()
        print("Executing SQL Insert...")
        try:
            cur.execute("""
                INSERT INTO users (username, password_hash, email, first_name, 
                last_name, date_of_birth, national_id, phone_number,
                address, citizenship, status, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (username, password_hash, email, first_name, last_name, date_of_birth, national_id,
            phone_number, address, citizenship, status, role))
            
            mysql.connection.commit()
            print("User registered successfully!")

            flash('Успешна регистрация!', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            mysql.connection.rollback()
            print(f"Database Error: {str(e)}")  # Показване на грешката
            flash(f'Грешка: {str(e)}', 'danger')

        finally:
            cur.close()

    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
def index():
    user = session.get('username')
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login_input']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("""
           SELECT * FROM users
           WHERE username = %s OR email = %s OR phone_number = %s 
         """,(login_input, login_input, login_input))
        
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            session.clear()
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Добре дошъл, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Грешно потребителско име, имейл, телефонен номер или парола!', 'danger')

    return render_template('login.html')

#admin panel
@app.route('/admin', methods=['GET'])
@login_required
@admin_required
def admin_dashboard():
    cur = mysql.connection.cursor()
    
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Брой потребители на страница
    offset = (page - 1) * per_page

    cur.execute('SELECT COUNT(*) FROM users')
    result = cur.fetchone()

    total_users = result['total'] if result and 'total' in result else 0  # Ако няма резултат, взимаме 0
    total_pages = max((total_users + per_page - 1) // per_page, 1)  # Минимум 1 страница

    cur.execute('SELECT id, username, email, password_hash, first_name, last_name, '
                'date_of_birth, national_id, phone_number, address, '
                'citizenship, status, role, created_at FROM users '
                'LIMIT %s OFFSET %s', (per_page, offset))
    
    users = cur.fetchall()
    cur.close()

    return render_template('admin_dashboard.html', users = users, total_pages = total_pages, current_page=page)

@app.route('/admin/user_accounts/<int:user_id>')
@login_required
@admin_required
def admin_user_accounts(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM accounts WHERE user_id = %s", (user_id,))
    accounts = cur.fetchall()
    cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if not accounts:
        flash("Този потребител няма сметки.", "info")

    return render_template('admin_user_accounts.html', accounts=accounts, user=user)


@app.route('/confirm_delete/<int:user_id>')
@login_required
def confirm_delete(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    return render_template('confirm_delete.html', user=user)

#deleting a user(only for admins)
@app.route('/delete_user/<int:user_id>', methods=['GET','POST'])
@login_required
@admin_required
def delete_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection.commit()
    cur.close()
    flash('Потребителят е изтрит', 'success')
    return redirect(url_for('admin_dashboard'))

#editing a acc for every user
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session.get('user_id')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if request.method == 'POST':
        username = request.form.get('username', user['username'])
        email = request.form.get('email', user['email'])
        first_name = request.form.get('first_name', user['first_name'])
        last_name = request.form.get('last_name', user['last_name'])
        phone_number = request.form.get('phone_number', user['phone_number'])
        address = request.form.get('address', user['address'])
        citizenship = request.form.get('citizenship', user['citizenship'])
        password = request.form.get('password_hash')

        if password:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        else:
            password_hash = user['password_hash']

        cur = mysql.connection.cursor()
        try:
            cur.execute('''
                UPDATE users 
                SET username=%s, email=%s, first_name=%s, last_name=%s, 
                    phone_number=%s, address=%s, citizenship=%s, password_hash=%s
                WHERE id=%s
            ''', (username, email, first_name, last_name, phone_number, address, citizenship, password_hash, user_id))

            mysql.connection.commit()
            flash('Профилът е обновен успешно!', 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Грешка при обновяване: {str(e)}', 'danger')
        finally:
            cur.close()

        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        date_of_birth = request.form['date_of_birth']
        national_id = request.form['national_id']
        phone_number = request.form['phone_number']
        address = request.form['address']
        citizenship = request.form['citizenship']
        status = request.form['status']
        role = request.form['role']

        try:
            cur.execute("""
                UPDATE users
                SET username = %s,
                    email = %s,
                    first_name = %s,
                    last_name = %s,
                    date_of_birth = %s,
                    national_id = %s,
                    phone_number = %s,
                    address = %s,
                    citizenship = %s,
                    status = %s,
                    role = %s
                WHERE id = %s
            """, (username, email, first_name, last_name, date_of_birth,
                  national_id, phone_number, address, citizenship, status, role, user_id))
            
            mysql.connection.commit()
            flash('Потребителят е редактиран успешно!', 'success')
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            mysql.connection.rollback()
            flash(f'Грешка при редакция: {e}', 'danger')

    cur.close()
    return render_template('edit_user.html', user=user)


# Закриване на акаунт (само за текущия потребител)
@app.route('/remove_user', methods=['GET','POST'])
@login_required
def remove_user():
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (session['user_id'],))
    mysql.connection.commit()
    cur.close()
    session.clear()
    flash('Акаунтът е изтрит', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Излязохте от системата.', 'info')
    return redirect(url_for('index'))

#==========================================#
#Създаване на сметки 
def generate_iban():
    country_code = "BG"
    bank_code = "FINV"
    account_number = ''.join(random.choices(string.digits, k=12))  # 12 случайни цифри
    return f"{country_code}12{bank_code}{account_number}"


@app.route('/create_account', methods=['GET', 'POST'])
@login_required
def create_account():
    user_id = session.get('user_id')

    if request.method == 'POST':
        account_type = request.form.get('account_type')
        currency = request.form.get('currency')

        iban = generate_iban()

        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) as count FROM accounts WHERE user_id = %s AND account_type = %s", (user_id, account_type))
        result = cur.fetchone()

        if result['count'] > 0:
            flash('Вече имате такъв тип сметка!', 'warning')
            return redirect(url_for('user_accounts'))

        #Въвежда нова сметка в базата
        cur.execute("""
                    INSERT INTO accounts (user_id, iban, balance, currency, account_type)
                    VALUES (%s, %s, %s, %s, %s)
                    """, (user_id, iban, 0.00, currency, account_type))
        
        mysql.connection.commit()
        cur.close()

        flash('Сметката беше успешно създадена!', 'success')
        return redirect(url_for('user_accounts'))
    
    return render_template('create_account.html')

@app.route('/close_account/<int:account_id>', methods=['GET', 'POST'])
@login_required
def close_account(account_id):
    user_id = session.get('user_id')
    cur = mysql.connection.cursor()
    
    cur.execute('SELECT * FROM accounts WHERE account_id = %s AND user_id = %s', (account_id, user_id))
    account = cur.fetchone()

    if not account:
        flash("Сметката не е намерена или нямате права да я закриете!", "danger")
        return redirect(url_for('user_accounts'))
    if request.method == 'POST':
        if account['balance'] > 0:
            flash("Не можете да закриете сметка с налични средства! Моля, изтеглете средствата първо.", "warning")
            return redirect(url_for('close_account',  account_id=account_id))

    try:
        # Архивиране на сметката (по избор)
        cur.execute('''
        INSERT INTO closed_accounts (user_id, iban, balance, currency, account_type, closed_at)
        VALUES (%s, %s, %s, %s, %s, NOW())
        ''', (account['user_id'], account['iban'], account['balance'], account['currency'], account['account_type']))
        mysql.connection.commit()


        # Изтриваме транзакциите, свързани със сметката (за да избегнем foreign key error)
        cur.execute("DELETE FROM transactions WHERE account_id = %s", (account_id,))
        mysql.connection.commit()

        # Изтриваме самата сметка
        cur.execute("DELETE FROM accounts WHERE account_id = %s", (account_id,))
        mysql.connection.commit()

        flash("Сметката беше успешно закрита!", "success")
        return redirect(url_for('user_accounts'))
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Грешка при изтриване: {str(e)}", "danger")

    finally:
        cur.close()

    cur.close()
    return render_template('close_account.html', account=account)

@app.route('/user_accounts')
@login_required
def user_accounts():
    user_id = session.get('user_id')

    #Извличаме всички сметки на текущия потребител
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM accounts WHERE user_id = %s", (user_id,))
    accounts = cur.fetchall()
    cur.close()

    return render_template('user_accounts.html', accounts=accounts)


@app.route('/view_account/<int:account_id>')
@login_required
def view_account(account_id):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM accounts WHERE account_id = %s", (account_id,))
    account = cur.fetchone()

    if not account:
        cur.close()
        flash("Сметката не е намерена!", "danger")
        return redirect(url_for('user_account'))
    
    cur.execute("""
            SELECT t.*, 
                a1.iban AS sender_iban, 
                a2.iban AS recipient_iban
            FROM transactions t
            LEFT JOIN accounts a1 ON t.account_id = a1.account_id
            LEFT JOIN accounts a2 ON t.recipient_account_id = a2.account_id
            WHERE t.account_id = %s OR t.recipient_account_id = %s
            ORDER BY t.timestamp DESC
    """, (account_id, account_id))
    transactions = cur.fetchall()

    cur.close()

    return render_template('view_account.html', account=account, transactions=transactions)


@app.route('/deposit/<int:account_id>', methods=['GET', 'POST'])
@login_required
def deposit(account_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM accounts WHERE account_id = %s", (account_id,))
    account = cur.fetchone()

    if not account:
        flash("Сметката не е намерена!", "danger")
        return redirect(url_for('user_accounts'))

    if request.method == 'POST':
        amount = Decimal(request.form.get('amount'))

        if amount and amount > 0:
            new_balance = account['balance'] + amount
            cur.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (new_balance, account_id))
            mysql.connection.commit()

            # Логваме транзакцията
            cur.execute("INSERT INTO transactions (account_id, amount, transaction_type, description) VALUES (%s, %s, 'deposit', %s)", (account_id, amount, 'Депозит'))
            mysql.connection.commit()

            flash(f"Успешно депозирани {amount} {account['currency']}", "success")
            return redirect(url_for('view_account', account_id=account_id))
        else:
            flash("Моля, въведете валидна сума!", "danger")

    cur.close()
    return render_template('deposit.html', account=account)

@app.route('/withdraw/<int:account_id>', methods=['GET', 'POST'])
@login_required
def withdraw(account_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM accounts WHERE account_id = %s", (account_id,))
    account = cur.fetchone()

    if not account:
        flash("Сметката не е намерена!", "danger")
        return redirect(url_for('user_accounts'))

    if request.method == 'POST':
        amount = Decimal(request.form.get('amount'))

        if amount and amount > 0:
            if amount > account['balance']:
                flash("Недостатъчна наличност!", "danger")
            else:
                new_balance = account['balance'] - amount
                cur.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (new_balance, account_id))
                mysql.connection.commit()

                # Логваме транзакцията
                cur.execute("INSERT INTO transactions (account_id, amount, transaction_type, description) VALUES (%s, %s, 'withdrawal', %s)", (account_id, amount, 'Теглене'))
                mysql.connection.commit()

                flash(f"Успешно изтегли {amount} {account['currency']}", "success")
                return redirect(url_for('view_account', account_id=account_id))
        else:
            flash("Моля, въведете валидна сума!", "danger")

    cur.close()
    return render_template('withdraw.html', account=account)


#==========================================#
# Транзакции

class TransferForm(FlaskForm):
    sender_account_id = SelectField('Изпращаща сметка', validators=[DataRequired()], choices=[])
    recipient_iban = StringField('IBAN на получателя', validators=[DataRequired()])
    amount = DecimalField('Сума', validators=[DataRequired(), NumberRange(min=0.01)], places=2)
    description = TextAreaField('Описание')
    submit = SubmitField('Изпрати')

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    form = TransferForm()

    sender_id = session.get('user_id')
    cur = mysql.connection.cursor()
    
    # 🔹 Извличаме всички сметки на потребителя
    cur.execute("SELECT account_id, iban, balance, currency FROM accounts WHERE user_id = %s", (sender_id,))
    sender_accounts = cur.fetchall()

    if not sender_accounts:
        flash("Нямате активни банкови сметки!", "danger")
        return redirect(url_for('user_accounts'))

    # ✅ Поправка: `sender_balance` няма да е `UnboundLocalError`
    sender_balance = sender_accounts[0]['balance']

    # 🔹 Добавяне на опции в `SelectField`
    form.sender_account_id.choices = [
        (str(acc['account_id']), f"{acc['iban']} ({acc['balance']} {acc['currency']})") 
        for acc in sender_accounts
    ]

    if request.method == 'POST':
        print(f"🔍 POST Request Data: {request.form}")  # Логваме входните данни

        if form.validate_on_submit():
            print("✅ Формата е валидна!")

            sender_account_id = int(form.sender_account_id.data)  # 🔹 Вземаме избраната сметка
            recipient_iban = form.recipient_iban.data.strip()
            amount = Decimal(form.amount.data)
            description = form.description.data or 'Без описание'

            # ✅ Проверка за IBAN
            if not recipient_iban.startswith("BG") or len(recipient_iban) != 20:
                print("❌ Невалиден IBAN!")
                flash("Невалиден IBAN! Трябва да започва с 'BG' и да съдържа 22 символа.", "danger")
                return redirect(url_for('transfer'))

            # ✅ Проверка за наличност
            cur.execute("SELECT balance FROM accounts WHERE account_id = %s AND user_id = %s", (sender_account_id, sender_id))
            sender_account = cur.fetchone()

            if not sender_account:
                print("❌ Избраната сметка не е намерена!")
                flash("Избраната сметка не е намерена!", "danger")
                return redirect(url_for('transfer'))

            else:
                print(f"✅ Намерена сметка: ID {sender_account_id}, Баланс: {sender_account['balance']}")

            sender_balance = Decimal(sender_account['balance'])

            if sender_balance < amount:
                print(f"❌ Недостатъчна наличност! Наличност: {sender_balance}, Опит за теглене: {amount}")
                flash('Недостатъчна наличност в сметката!', 'danger')
                return redirect(url_for('transfer'))

            else:
                print("✅ Балансът е достатъчен!")

            # ✅ Проверка дали получателят съществува
            cur.execute("SELECT account_id FROM accounts WHERE iban = %s", (recipient_iban,))
            recipient_account = cur.fetchone()

            if not recipient_account:
                flash("Получателят не е намерен!", "danger")
                return redirect(url_for('transfer'))

            recipient_account_id = recipient_account['account_id']

            print(f"🔍 Проверка преди трансфер: sender_account_id={sender_account_id}, recipient_iban={recipient_iban}, amount={amount}")

            try:
                cur.execute("START TRANSACTION")
                print("🟢 Транзакцията започна...")  # ✅ Лог преди транзакцията

                cur.execute("UPDATE accounts SET balance = balance - %s WHERE account_id = %s", (amount, sender_account_id))
                print("💰 Балансът на подателя е намален!")  # ✅ Лог за баланса

                cur.execute("UPDATE accounts SET balance = balance + %s WHERE account_id = %s", (amount, recipient_account_id))
                print("💰 Балансът на получателя е увеличен!")  # ✅ Лог за баланса

                cur.execute("""
                    INSERT INTO transactions (account_id, amount, transaction_type, description, recipient_account_id)
                    VALUES (%s, %s, 'transfer', %s, %s)
                """, (sender_account_id, amount, description, recipient_account_id))
                print("📝 Транзакцията е записана в базата!")  # ✅ Лог за записа

                mysql.connection.commit()
                print("✅ Транзакцията беше успешно извършена!")  # ✅ Лог за commit

                flash(f"Трансферът на {amount} лв. към {recipient_iban} беше успешен!", "success")
                return redirect(url_for('user_accounts'))

            except Exception as e:
                mysql.connection.rollback()
                print(f"❌ Грешка при трансфера: {str(e)}")  # ✅ Лог за грешка
                flash(f"Грешка при извършване на трансфера: {str(e)}", "danger")

            finally:
                cur.close()
        else:
            print(f"⚠️ Form errors: {form.errors}")  # Логваме грешките при валидация

    return render_template('transfer.html', form=form, sender_accounts=sender_accounts, sender_balance=sender_balance)

@app.route('/admin/transactions')
@login_required
def admin_transactions():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT t.transaction_id, a.iban AS sender_iban, t.amount, t.transaction_type, 
               t.timestamp, t.description, r.iban AS recipient_iban
        FROM transactions t
        JOIN accounts a ON t.account_id = a.account_id
        LEFT JOIN accounts r ON t.recipient_account_id = r.account_id
        ORDER BY t.timestamp DESC
    """)
    transactions = cur.fetchall()
    cur.close()
    
    return render_template('admin_transactions.html', transactions=transactions)


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"]=True
    app.config['DEBUG']=True
    app.run()
