-- License Server Database Initialization
-- This script runs only on first container startup.

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Note: Actual tables are created by the license server's own migrations/
-- startup code. This script just ensures the database is ready.
