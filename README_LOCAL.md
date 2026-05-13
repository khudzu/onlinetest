# Menjalankan Project Secara Lokal

Folder project:

```bash
cd /Users/khudzu/Documents/Codex/2026-05-13/bagaimana-migrate-project-django-menggunakan-railway/onlinetest
```

## 1. Buat virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 2. Install dependency

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 3. Buat file env lokal

```bash
cp .env.example .env
```

Untuk lokal, `DATABASE_URL` boleh dikosongkan supaya Django memakai SQLite.

## 4. Setup database lokal

```bash
python manage.py migrate
```

## 5. Buat admin lokal

```bash
python manage.py createsuperuser
```

## 6. Jalankan server

```bash
python manage.py runserver
```

Buka:

```text
http://127.0.0.1:8000/
http://127.0.0.1:8000/admin/
```

## Push ke GitHub

Pastikan perubahan sudah dicek:

```bash
git status
```

Commit dan push:

```bash
git add .
git commit -m "Tulis pesan perubahan"
git push origin master
```

Jika GitHub meminta password, gunakan Personal Access Token sebagai password.
