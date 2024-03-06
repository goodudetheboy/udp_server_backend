import logging
import asyncio

# Configure the logging module
logging.basicConfig(level=logging.INFO)

async def login_task(user):
    # Introduce a 5-second delay asynchronously
    await asyncio.sleep(5)    
    logging.info(f"Logging in for {user}...")

async def data_processing_task(data):
 
    # Introduce a 5-second delay asynchronously
    await asyncio.sleep(5)   # Your asynchronous data processing code goes here
    logging.info(f"Processing data: {data}")

async def main():
    # Create tasks for login and data processing asynchronously
    login_task_instance = asyncio.create_task(login_task("user123"))
    data_processing_task_instance = asyncio.create_task(data_processing_task("some_data"))


    # Code here will run concurrently with login_task and data_processing_task
    print("Code running concurrently with tasks")
    return False

# Run the main asynchronous function
print(asyncio.create_task(data_processing_task("fadsf")))

# Continue with the rest of your code
print("Continuing with the rest of the code...")
