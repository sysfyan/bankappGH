import os

class Config:
    SECRET_KEY = 'afdc8d1e47778cb083c8ed77ef60e68d'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///bankapp.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False