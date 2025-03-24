import os

bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
workers = int(os.getenv('WEB_CONCURRENCY', '4'))
timeout = 120
keepalive = 5
worker_class = "sync"
reload = False
