# Django Message System

A secure and professionally designed message system built using Django, with separate apps for sending and receiving messages (`SenderApp` and `ReceiverApp`). The system supports encryption, decryption, user authentication, and message management.

## Features

### SenderApp
- User registration and login system with secure password hashing.
- Send messages with:
  - Priority levels (Low, Normal, High).
  - Optional attachments (up to 5 MB).
- Encrypted message storage using `Fernet`.
- Forward encrypted messages to `ReceiverApp`.

### ReceiverApp
- User registration and login system.
- Decrypt and store received messages.
- View, search, filter, and sort messages by sender, priority, and timestamp.
- User-friendly interface with a professional design.

## Installation

### Prerequisites
- Python 3.8+
- PostgreSQL database
- Django 5.1.4
- `pip` package manager
- **Visual C++ Build Tools**: Required for compiling dependencies such as `cryptography`. Download and install from [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).
  - During installation, ensure you select the **"Desktop development with C++"** workload.
  - Also, include **"MSVC v142 - VS 2019 C++ x64/x86 build tools"** and **"Windows 10 SDK"**.

### Clone the Repository
```bash
git clone https://github.com/yourusername/django-message-system.git
cd django-message-system
```

### Setup Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Database Configuration
1. Create a PostgreSQL database:
   ```sql
   CREATE DATABASE message_system;
   CREATE USER sender_user WITH PASSWORD 'sender123';
   CREATE USER receiver_user WITH PASSWORD 'receiver123';
   GRANT ALL PRIVILEGES ON DATABASE message_system TO sender_user, receiver_user;
   ```

2. Update database credentials in `SenderProject/settings.py` and `ReceiverProject/settings.py`.

### Apply Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Create Superuser (Optional)
```bash
python manage.py createsuperuser
```

### Run the Development Server
- Start the `SenderApp`:
  ```bash
  python manage.py runserver 8000
  ```
- Start the `ReceiverApp`:
  ```bash
  python manage.py runserver 8001
  ```

## Usage

### SenderApp
- Access the `SenderApp` at `http://127.0.0.1:8000/`.
- Register or log in to send messages.
- Messages are encrypted and forwarded to the `ReceiverApp`.

### ReceiverApp
- Access the `ReceiverApp` at `http://127.0.0.1:8001/`.
- Log in to view received messages.
- Search, filter, and sort messages with a clean interface.

## File Structure

```
django-message-system/
├── SenderProject/
│   ├── SenderApp/
│   └── templates/
├── ReceiverProject/
│   ├── ReceiverApp/
│   └── templates/
├── CommonApp/  # Shared models and utilities
└── README.md
```

## Security Features
- Encrypted messages using `Fernet` symmetric encryption.
- Secure password hashing with Django's default hasher.
- Permissions and roles configured in the database.

## Known Issues
- Ensure both apps are running on their respective ports (8000 for `SenderApp`, 8001 for `ReceiverApp`).
- Attachments larger than 5 MB are not supported.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

**Happy messaging!** 🚀