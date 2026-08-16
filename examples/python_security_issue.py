API_TOKEN = "example_token_not_for_production"

def find_user(database, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return database.execute(query)
