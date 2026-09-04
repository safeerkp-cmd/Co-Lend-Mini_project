# Co-Lend: Smart Resident Ledger

A community asset lending and ledger management web application designed for residential societies and housing associations.

## Features

- **Authentication & Role-Based Access Control:** Secure registration with admin approval workflow, role-based dashboards for residents and administrators.
- **Asset Catalog & Inventory Management:** Administrators can register community assets, track quantities, set daily rental rates, and monitor inventory.
- **Asset Booking:** Residents can reserve available assets for lease durations between 1 and 30 days with automated stock deduction.
- **Returns & Fine Calculation:** Administrators process asset check-ins with automatic overdue fine calculation for late returns.
- **Completed & Overdue Ledger:** Historical ledger logging return due dates, rental fees, payment statuses, and overdue penalties.
- **Complaints & Maintenance:** Residents can submit issue reports for their booked assets; administrators track and mark complaints as resolved.
- **Profile & Password Management:** Dedicated resident profile view with secure password change functionality.
- **Security & Integrity:**
  - Password hashing via Werkzeug (scrypt).
  - Cross-Site Request Forgery (CSRF) protection on all state-changing endpoints.
  - Server-side booking ownership validation to prevent Insecure Direct Object References (IDOR).
  - Safe asset deletion safeguards preventing removal of actively leased items.
  - Environment-based secret management (.env isolation).
  - Production error handling (400, 404, 500) suppressing internal stack traces and database credentials.

## Technology Stack

- **Backend:** Python 3, Flask
- **Database:** PostgreSQL with psycopg2
- **Frontend:** Jinja2 Templates, Tailwind CSS
- **Authentication:** Werkzeug Security (generate_password_hash, check_password_hash)

## Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL 14+

### Installation

1. Clone the repository:
   \\ash
   git clone https://github.com/safeerkp-cmd/Co-Lend-Mini_project.git
   cd Co-Lend-Mini_project
   \
2. Create and activate a Python virtual environment:
   \\ash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   \
3. Install required packages:
   \\ash
   pip install Flask psycopg2-binary werkzeug
   \
4. Set up the PostgreSQL database:
   - Create a database named \colend_db\.
   - Execute schema definitions from \database.sql\:
     \\ash
     psql -U postgres -d colend_db -f database.sql
     \
5. Configure environment variables:
   - Copy \.env.example\ to \.env\:
     \\ash
     cp .env.example .env
     \   - Update \.env\ with your PostgreSQL database password and a secure \SECRET_KEY\.

6. Run the application:
   \\ash
   python app.py
   \   The application will be accessible at \http://127.0.0.1:5000/\.
