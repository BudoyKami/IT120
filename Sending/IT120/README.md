# 📧 **Secure Messaging Application**

A secure messaging application built with **Django** and **Django REST Framework (DRF)**. This application allows users to register, log in, and send secured messages with encryption. The app features a professionally designed interface using **Bootstrap** for responsive design.

---

## 🚀 **Features**

1. **User Authentication**:

   - Register new users.
   - Log in with existing credentials.
   - Secure password management.

2. **Message Sending**:

   - Authenticated users can send messages.
   - End-to-end encryption for secure message transmission.

3. **Modern UI**:

   - Professionally designed interface with **Bootstrap 5**.
   - Responsive design for desktop and mobile devices.


4. **Middleware Encryption**:

   - Custom middleware for encrypting and decrypting messages using **Argon5**, **BLAKE2**, and **AES**.



## 🛠️ **Technologies Used**

- **Backend**: Django 5.1, Django REST Framework
- **Frontend**: HTML, CSS, Bootstrap 5
- **Database**: SQLite (default)
- **Security**: Argon5, BLAKE2, AES for message encryption
- **Tools**: Python 3.11+, pip, virtualenv

---

## 📂 **Project Structure**
```
secure_messaging_app/
│── sending_project/
│   │── manage.py
│   │── sending_project/
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   ├── urls.py
│   │   └── wsgi.py
│   │── sending_application/
│       ├── __init__.py
│       ├── admin.py
│       ├── apps.py
│       ├── models.py
│       ├── views.py
│       ├── urls.py
│       ├── middleware.py
│       └── templates/
│           └── sending_application/
│               ├── base.html
│               ├── home.html
│               ├── register.html
│               ├── login.html
│               └── send_message.html
└── requirements.txt
```

---

## 📝 **Setup Instructions**

### 1. **Clone the Repository**

```bash
git clone https://github.com/your-username/secure_messaging_app.git
cd secure_messaging_app/sending_project
```

### 2. **Create and Activate a Virtual Environment**

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. **Install Dependencies**

```bash
pip install -r requirements.txt
```

### 4. **Apply Migrations**

```bash
python manage.py makemigrations
python manage.py migrate
```

### 5. **Create a Superuser**

```bash
python manage.py createsuperuser
```

### 6. **Run the Development Server**

```bash
python manage.py runserver
```

### 7. **Access the Application**

- **Home Page**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Register**: [http://127.0.0.1:8000/register/](http://127.0.0.1:8000/register/)
- **Login**: [http://127.0.0.1:8000/login/](http://127.0.0.1:8000/login/)
- **Send Message**: [http://127.0.0.1:8000/send-message/](http://127.0.0.1:8000/send-message/)

---

## 🔐 **Security Features**

1. **Middleware Encryption**:
   - Messages are encrypted using a combination of **Argon5**, **BLAKE2**, and **AES** before being sent.
   - Decryption occurs automatically on the receiving end.

2. **CSRF Protection**:
   - Built-in CSRF protection for all forms.

3. **Password Hashing**:
   - Secure password hashing with Django's authentication system.

---

## 🐛 **Troubleshooting**

1. **Database Errors**:
   - Ensure you've applied migrations:
     ```bash
     python manage.py migrate
     ```

2. **Template Not Found**:
   - Verify your template paths in `sending_application/templates/sending_application/`.

3. **Server Not Running**:
   - Start the server with:
     ```bash
     python manage.py runserver
     ```

---

## 🤝 **Contributing**

Contributions are welcome! Please fork the repository and submit a pull request with your changes.
