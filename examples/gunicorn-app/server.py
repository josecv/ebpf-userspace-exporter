#!/usr/bin/env python3.9

import gc
import random

from flask import Flask

app = Flask(__name__)


@app.route('/')
def hello_world():
    # Generate some allocations so there's something to gc
    memory = []
    for _ in range(random.randint(5, 10)):
        memory.append(bytearray(random.randint(10, 20)))
    del memory
    if random.randint(0, 4) == 0:
        # Explicitly garbage collect approx every 5 requests
        gc.collect()
    return 'Hello from example app!'
