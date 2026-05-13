web: python manage.py migrate && python manage.py collectstatic --noinput && python manage.py ensure_superuser && gunicorn blog.wsgi:application --bind 0.0.0.0:$PORT
