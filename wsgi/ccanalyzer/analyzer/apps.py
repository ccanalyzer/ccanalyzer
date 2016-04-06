import os

from django.apps import AppConfig


class Config(AppConfig):
    name      = 'analyzer'
    name_desc = 'Cisco Config Analyzer'
    repo_path = os.path.normpath(os.path.join(os.path.dirname(__file__), '../../../', 'data/repository'))
    repo_conf_extensions = tuple(['.cfg', '.conf', '.config'])

