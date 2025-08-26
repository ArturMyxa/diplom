from celery import Celery
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'orders.settings')

celery_app = Celery('orders')
celery_app.config_from_object('django.conf:settings', namespace='CELERY')
celery_app.autodiscover_tasks()