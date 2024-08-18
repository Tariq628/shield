import csv
from app import db, User, bcrypt

def initialize_users(csv_filename):
    with open(csv_filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Check if user already exists
            existing_user = User.query.filter_by(email=row['email']).first()
            if existing_user:
                print(f"User with email {row['email']} already exists. Skipping.")
                continue

            # Handle empty passwords
            if row['password']:
                hashed_password = bcrypt.generate_password_hash(row['password']).decode('utf-8')
                has_set_password = True
            else:
                hashed_password = None
                has_set_password = False
            
            # Create new user
            new_user = User(
                first_name=row['first_name'],
                last_name=row['last_name'],
                email=row['email'],
                password=hashed_password,
                has_set_password=has_set_password,
                is_admin=row['is_admin'].lower() == 'true'
            )
            
            # Add to session
            db.session.add(new_user)
        
        # Commit the session
        db.session.commit()
        print("Users initialized successfully.")

if __name__ == "__main__":
    initialize_users('emails.csv')
