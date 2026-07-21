# AlphaOneLabs Education Platform

## Project Overview

Alpha One Labs is an education platform designed to facilitate both learning and teaching. The platform provides a comprehensive environment where educators can create and manage courses, while students can learn, collaborate, and engage with peers. With features like study groups, peer connections, and discussion forums, we aim to create a collaborative learning environment that goes beyond traditional online education.

## Tech Stack

- Frontend: HTML,Tailwind CSS 
- Backend: Python (Cloudflare Worker)
- Database: Cloudflare D1 (SQLite)

## Set Up Instructions

### Prerequisites

Before starting, ensure you have the following installed:
 - **Node.js**: v18.0.0 or higher
 - **npm**: v9.0.0 or higher
 - **Wrangler CLI**: For deploying Cloudflare Workers

Install Wrangler globally using npm:

```bash
npm install -g wrangler
```

### Fork & Clone the Repository (For Contributors)

If you are a contributor, first fork the repository to your own GitHub account.

```bash
# Clone your fork (replace <your-username> with your actual username)
git clone https://github.com/<your-username>/learn.git
cd learn

# Add the original repository as an upstream remote
git remote add upstream https://github.com/alphaonelabs/learn.git
```

### Login to Cloudflare (One-time)

Authenticate the Wrangler CLI with your Cloudflare account. This will open a browser window to complete the login process safely.

```bash
wrangler login
```

### Setup Database (D1)

Follow these step-by-step instructions to set up your Cloudflare D1 database:

1. **Create the Database:**

```bash
wrangler d1 create education_db
```

2. **Add configuration to `wrangler.toml`:**
   After running the create command, copy the `database_id` from the output and update your `wrangler.toml` file with this placeholder:

```toml
[[d1_databases]]
binding = "DB"
database_name = "education_db"
database_id = "<YOUR_DATABASE_ID>"
```

3. **Apply the Schema:**
   Run the following to set up your database tables (for local development):

```bash
wrangler d1 execute education_db --local --file=schema.sql
```

### Setup Environment Variables

This project requires environment variables for encryption and authentication.

#### For Local Development

Copy `.dev.vars.sample` to `.dev.vars` in the project root, then replace the placeholder values with your own secrets.

```
ENCRYPTION_KEY=your-dev-encryption-key
JWT_SECRET=your-dev-jwt-secret
SENTRY_DSN=your-sentry-dsn
```

#### For Production

Use the Wrangler CLI to set secrets securely for your deployed worker:

```bash
wrangler secret put ENCRYPTION_KEY
wrangler secret put JWT_SECRET
wrangler secret put SENTRY_DSN
```

Or upload all values from an env file after verifying the active Cloudflare account:

```bash
./scripts/upload-vars.sh .env.production --account-id YOUR_ACCOUNT_ID
```

To run with no arguments, add your account ID to `.env.production`:

```
CLOUDFLARE_ACCOUNT_ID=YOUR_ACCOUNT_ID
```

Then run:

```bash
./scripts/upload-vars.sh
```

You can also verify by account name:

```bash
./scripts/upload-vars.sh .env.production --account-name "Your Account Name"
```

Optional Sentry tuning secrets:

```bash
wrangler secret put SENTRY_TRACES_SAMPLE_RATE
wrangler secret put SENTRY_ENVIRONMENT
wrangler secret put SENTRY_RELEASE
```

### Running the Application

The application consists of a backend worker and frontend HTML files. Run them concurrently in separate terminal sessions.

#### Run Backend

Start the Cloudflare Worker locally:

```bash
wrangler dev
```

The backend server usually starts at: `http://127.0.0.1:8787`

#### Run Frontend

Serve the static files using a local development server (like `serve`):

```bash
npx serve public
```

The frontend server usually starts at: `http://localhost:3000`

### Common Errors

- **`wrangler: command not found`**: Ensure that npm's global bin directory is in your system's PATH.
- **`D1_ERROR` when running backend**: Check that you have replaced `<YOUR_DATABASE_ID>` with your actual database ID inside `wrangler.toml`.
- **CORS Errors**: If the frontend cannot communicate with the backend, ensure your backend is running (`wrangler dev`) and check the console. Ensure you are accessing the frontend via a local server (e.g., `http://localhost:3000`) rather than a `file://` URL.