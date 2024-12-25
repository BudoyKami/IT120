CREATE USER sender_user WITH PASSWORD 'sender123';
CREATE USER receiver_user WITH PASSWORD 'receiver123';

--------------------------------------------------
--------------------------------------------------
-- Permissions for receiver_user
--------------------------------------------------
--------------------------------------------------

-- Grant permissions on the database
GRANT CONNECT ON DATABASE message_system TO receiver_user;

-- Grant permissions on the public schema
GRANT USAGE ON SCHEMA public TO receiver_user;
GRANT CREATE ON SCHEMA public TO receiver_user;

-- Allow the user to work with existing tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO receiver_user;

-- Allow the user to work with sequences (needed for AutoField primary keys)
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO receiver_user;

-- Set default privileges for future tables and sequences
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO receiver_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO receiver_user;

--------------------------------------------------
--------------------------------------------------
-- Permissions for sender_user
--------------------------------------------------
--------------------------------------------------

-- Grant permissions on the database
GRANT CONNECT ON DATABASE message_system TO sender_user;

-- Grant permissions on the public schema
GRANT USAGE ON SCHEMA public TO sender_user;
GRANT CREATE ON SCHEMA public TO sender_user;

-- Allow the user to work with existing tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sender_user;

-- Allow the user to work with sequences (needed for AutoField primary keys)
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO sender_user;

-- Set default privileges for future tables and sequences
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sender_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO sender_user;

--------------------------------------------------
--------------------------------------------------
-- Other Permissions
--------------------------------------------------
--------------------------------------------------

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO receiver_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sender_user;

SELECT * FROM senderapp_message;
SELECT * FROM receiverapp_message;