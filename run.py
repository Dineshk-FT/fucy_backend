from app import create_app

app = create_app()

if __name__ == '__main__':
    # Disable reloader to avoid threading issues with ML libraries
    app.run(debug=True, use_reloader=False, port=5000)