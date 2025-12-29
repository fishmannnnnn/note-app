"""
Production запуск с кастомными настройками
"""
from app import app

class CustomServerNameMiddleware:
    """WSGI middleware для кастомного Server name"""
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            # Удаляем оригинальный Server header
            headers = [(name, value) for name, value in headers if name.lower() != 'server']
            # Добавляем кастомный
            headers.append(('Server', 'SecureWebServer/1.0'))
            return start_response(status, headers, exc_info)
        
        return self.app(environ, custom_start_response)

# Применяем middleware
app.wsgi_app = CustomServerNameMiddleware(app.wsgi_app)

if __name__ == '__main__':
    # Простой запуск Flask для тестирования
    print("Запуск с кастомным Server header: SecureWebServer/1.0")
    app.run(debug=False, host='127.0.0.1', port=5000)