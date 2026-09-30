import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text


load_dotenv()


database_url = os.getenv("DATABASE_URL")


if not database_url:
    raise ValueError(
        "DATABASE_URL is missing."
    )


engine = create_engine(database_url)


try:

    with engine.connect() as connection:

        result = connection.execute(
            text("SELECT 1")
        )

        print("========================================")
        print("DATABASE CONNECTION SUCCESSFUL")
        print("========================================")
        print("Test result:", result.scalar())

except Exception as error:

    print("========================================")
    print("DATABASE CONNECTION FAILED")
    print("========================================")
    print("Error:", error)