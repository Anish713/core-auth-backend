-- Database initialization script for auth_service
-- This script will be run when the PostgreSQL container starts for the first time

-- Create the auth_service database if it doesn't exist
-- (This is handled by POSTGRES_DB environment variable)

-- Create any additional users or permissions if needed
-- Currently using the default postgres user

-- You can add any additional initialization here
-- For example, creating additional databases for testing:

CREATE DATABASE auth_service_test;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE auth_service TO postgres;
GRANT ALL PRIVILEGES ON DATABASE auth_service_test TO postgres;