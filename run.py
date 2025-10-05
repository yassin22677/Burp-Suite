from app import create_app   # Imports the app setup

app = create_app()           # Creates the Flask app using the function in __init__.py

if __name__ == "__main__":
    app.run(debug=True)      # Starts the local server
