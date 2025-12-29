from app import app

if __name__ == '__main__':
    from waitress import serve
    print("Запуск приложения через Waitress на http://127.0.0.1:5000")
    serve(app, host='127.0.0.1', port=5000)