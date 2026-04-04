from inference import run_benchmark
import time

print("Starting AI Security OpenEnv...")

result = run_benchmark()
print(result)

# Keep container alive

while True:
    time.sleep(60)