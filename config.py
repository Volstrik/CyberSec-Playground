import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")