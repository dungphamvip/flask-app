import sys
import os

# Thêm đường dẫn của project vào sys.path
path = os.path.dirname(os.path.abspath(__file__))
if path not in sys.path:
    sys.path.append(path)

from app import app as application 