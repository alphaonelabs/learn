#!/bin/bash

echo "Setting up project..."

# Step 1: Check Node & Wrangler
if ! command -v node &> /dev/null
then
  echo "Node.js not found. Please install Node.js."
  exit 1
fi

if ! command -v wrangler &> /dev/null
then
  echo "Wrangler not found. Install using: npm install -g wrangler"
  exit 1
fi

# Step 2: Create D1 Database
echo "Checking/Creating D1 database..."

OUTPUT=$(wrangler d1 create education_db 2>&1)

if echo "$OUTPUT" | grep -q "already exists"; then
  echo "Database already exists. Fetching existing ID..."

  OUTPUT=$(wrangler d1 list)
fi

# Extract database_id
DB_ID=$(echo "$OUTPUT" | grep -oE '[a-f0-9-]{36}' | head -n 1)

if [ -z "$DB_ID" ]; then
  echo "Failed to extract database_id"
  echo "$OUTPUT"
  exit 1
fi

echo "Using Database ID: $DB_ID"

# Step 3: Update wrangler.toml
echo "Updating wrangler.toml..."

if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS BSD sed
  sed -i '' "s/ADD_YOUR_LOCAL_DATABASE_ID_HERE/${DB_ID}/" wrangler.toml
else
  # GNU sed (Linux)
  sed -i "0,/ADD_YOUR_LOCAL_DATABASE_ID_HERE/s//${DB_ID}/" wrangler.toml
fi

echo "wrangler.toml updated"

# Step 4: Apply schema
echo "Applying schema..."
wrangler d1 execute education_db --file=schema.sql --env dev

if [ $? -ne 0 ]; then
  echo "Failed to apply schema."
  exit 1
fi

echo "Schema applied"

echo "Setup complete!"
echo "Run: wrangler dev --env dev""