# импортируем из созданного нами ранее файла celery.py наш объект(экземпляр класса) celery (app)
from .celery import celery_app
# Подключаем объект
__all__ = ('celery_app',)