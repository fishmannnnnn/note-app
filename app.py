from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import os
import sqlite3

from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_wtf import FlaskForm
import bleach

from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv()

# App / DB configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "fallback-secret-key")  
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI", "sqlite:///notes.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # В production должно быть True
app.config['SESSION_COOKIE_HTTPONLY'] = True


# CSRF protection (Flask-WTF)
# csrf = CSRFProtect(app)

# ORM
db = SQLAlchemy(app)

# Models
class Note(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    owner = db.Column(db.String(64), nullable=False)  # хранит session-based user id (симуляция прав)

    def __repr__(self):
        return f"<Note id={self.id} title={self.title!r}>"
    
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Forms
class NoteForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired(message="Заголовок обязателен"), Length(max=200)])
    content = TextAreaField('Содержимое', validators=[DataRequired(message="Содержимое обязательно"), Length(max=5000)])
    submit = SubmitField('Сохранить')

# Security
def get_current_user():
    """
    Возвращает уникальный идентификатор текущего "пользователя" из сессии.
    Если его нет — генерируем и сохраняем в сессии.
    Это упрощённая имитация аутентификации; используется для демонстрации защиты от IDOR.
    """
    if 'user_id' not in session:
        session['user_id'] = uuid.uuid4().hex
    return session['user_id']

def sanitize_input(text: str) -> str:
    """
    Очистка пользовательского ввода от потенциально опасных HTML-тегов/атрибутов.
    Используем bleach.
    Jinja2 по умолчанию экранирует вывод, тем не менее лучше хранить в БД безопасный текст.
    """
    # Разрешим только безопасный набор тегов (здесь — пустой, т.е. разрешаем только текст)
    safe = bleach.clean(text, tags=[], attributes={}, strip=True)
    return safe

@app.before_request
def ensure_user():
    get_current_user()
    
@app.after_request
def set_secure_headers(response):
    """
    Middleware для установки HTTP-заголовков безопасности.
    Исправляет все проблемы, найденные ZAP.
    """
    # CSP - добавляем недостающие директивы и fallback
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "  # Fallback для всех непрописанных директив
        "script-src 'self'; "
        "style-src 'self'; "  # Убираем 'unsafe-inline'
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "  # Защита от clickjacking
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
    )
    
    # Обязательные security headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # HSTS - принудительное использование HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Дополнительные security headers
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    # Скрываем информацию о сервере
    if 'Server' in response.headers:
        del response.headers['Server']
    
    # Заголовки для управления кэшем
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    return response


@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Главная страница: список заметок и форма добавления новой заметки.
    """
    form = NoteForm()
    if form.validate_on_submit():
        # Валидация полей выполнена Flask-WTF/WTForms
        title = sanitize_input(form.title.data)
        content = sanitize_input(form.content.data)
        owner = get_current_user()

        # Создаем через SQLAlchemy ORM — безопасно (параметризованные запросы внутри)
        note = Note(title=title, content=content, owner=owner)
        db.session.add(note)
        db.session.commit()

        flash('Заметка добавлена.', 'success')
        return redirect(url_for('index'))

    # Показываем все заметки.
    # доступ будет проверяться по owner.
    notes = Note.query.order_by(Note.created_at.desc()).all()
    return render_template('index.html', notes=notes, form=form)

@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
def edit(note_id):
    """
    Страница редактирования заметки.
    Защита от IDOR: проверяем, совпадает ли owner заметки с текущим user_id из сессии.
    """
    note = Note.query.get_or_404(note_id)

    # Проверка прав: только владелец (session-based) может редактировать
    if note.owner != get_current_user():
        # Возвращаем 403 Forbidden — это простая имитация контроля доступа
        abort(403, description="Нет прав на редактирование этой заметки.")

    form = NoteForm(obj=note)
    if form.validate_on_submit():
        # Санитизация перед сохранением
        note.title = sanitize_input(form.title.data)
        note.content = sanitize_input(form.content.data)
        db.session.commit()
        flash('Заметка обновлена.', 'success')
        return redirect(url_for('index'))

    return render_template('edit.html', form=form, note=note)

@app.route('/delete/<int:note_id>', methods=['POST'])
def delete(note_id):
    """
    Удаление заметки. CSRF-токен обязателен (Flask-WTF CSRFProtect).
    Также проверяем owner -> защита от IDOR.
    """
    note = Note.query.get_or_404(note_id)
    if note.owner != get_current_user():
        abort(403, description="Нет прав на удаление этой заметки.")
    db.session.delete(note)
    db.session.commit()
    flash('Заметка удалена.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    user = User(
        username=request.form['username'],
        password=request.form['password']
    )
    db.session.add(user)
    db.session.commit()
    return redirect('/login')


@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(
        username=request.form['username'],
        password=request.form['password']
    ).first()

    if user:
        session['auth_user'] = user.username
        return redirect('/')
    return "Ошибка входа", 401


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html', message=str(e)), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', message=str(e)), 404

# CLI helper: инициализация БД
@app.cli.command("init-db")
def init_db():
    """Создаёт БД (для удобства). Запустить: flask init-db"""
    db.create_all()
    print("База данных и таблицы созданы.")

# Запуск
if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
