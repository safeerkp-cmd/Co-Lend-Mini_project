
-- Co-Lend Smart Resident Ledger PostgreSQL Database Schema

-- 1. Users Table (Core Login Credentials & Status)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'resident')),
    status VARCHAR(50) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED'))
);

-- 2. Resident Profiles Table (Metadata matching Users)
CREATE TABLE IF NOT EXISTS resident_profiles (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    full_name VARCHAR(100) NOT NULL,
    house_name_number VARCHAR(100) NOT NULL,
    street_address VARCHAR(255) NOT NULL,
    city VARCHAR(100) NOT NULL,
    pincode VARCHAR(20) NOT NULL,
    phone_number VARCHAR(100) NOT NULL
);

-- 3. Assets Table (Inventory List)
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    total_qty INT NOT NULL CHECK (total_qty >= 0),
    available_qty INT NOT NULL CHECK (available_qty >= 0),
    daily_rent DECIMAL(10, 2) NOT NULL CHECK (daily_rent >= 0.00)
);

-- 4. Bookings Table (Transaction Ledger)
CREATE TABLE IF NOT EXISTS bookings (
    id SERIAL PRIMARY KEY,
    resident_id INT REFERENCES users(id) ON DELETE CASCADE,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE,
    booked_qty INT NOT NULL CHECK (booked_qty > 0),
    duration_days INT NOT NULL CHECK (duration_days > 0),
    booking_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'Active' CHECK (status IN ('Active', 'Returned', 'Overdue')),
    payment_status VARCHAR(50) DEFAULT 'Pending' CHECK (payment_status IN ('Pending', 'Paid'))
);

-- 5. Fines Table (Overdue Penalties)
CREATE TABLE IF NOT EXISTS fines (
    id SERIAL PRIMARY KEY,
    booking_id INT REFERENCES bookings(id) ON DELETE CASCADE,
    fine_amount DECIMAL(10, 2) NOT NULL CHECK (fine_amount >= 0.00),
    payment_status VARCHAR(50) DEFAULT 'Pending' CHECK (payment_status IN ('Pending', 'Paid'))
);

-- 6. Complaints Table (Faulty Asset Reports)
CREATE TABLE IF NOT EXISTS complaints (
    id SERIAL PRIMARY KEY,
    booking_id INT REFERENCES bookings(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'Pending' CHECK (status IN ('Pending', 'Resolved'))
);

-- Indexing Foreign Keys for join query performance
CREATE INDEX IF NOT EXISTS idx_resident_profiles_user_id ON resident_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_bookings_resident_id ON bookings(resident_id);
CREATE INDEX IF NOT EXISTS idx_bookings_asset_id ON bookings(asset_id);
CREATE INDEX IF NOT EXISTS idx_fines_booking_id ON fines(booking_id);
CREATE INDEX IF NOT EXISTS idx_complaints_booking_id ON complaints(booking_id);
