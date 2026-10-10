"""
Module containing examples of common vulnerabilities in web applications.

This FastAPI app demonstrates insecure coding practices such as SQL injection,
directory traversal, improper exception handling, insecure file uploads, and
weak authentication mechanisms. The purpose is to highlight vulnerabilities
for educational purposes.
"""

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Base directory that /read_file may serve files from.
# Override with the READ_FILE_BASE_DIR environment variable.
DEFAULT_READ_FILE_BASE_DIR = Path(__file__).resolve().parent / "files"


def get_read_file_base_dir() -> Path:
    """
    Return the resolved base directory for the /read_file endpoint.

    Returns:
        Path: The absolute, resolved base directory.
    """
    return Path(
        os.environ.get("READ_FILE_BASE_DIR", str(DEFAULT_READ_FILE_BASE_DIR))
    ).resolve()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Add security response headers to every response.

    Sets X-Content-Type-Options and Cross-Origin-Resource-Policy.

    Args:
        request (Request): The incoming request.
        call_next: The next handler in the middleware chain.

    Returns:
        Response: The response with the security headers set.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


# Example of hardcoded secrets
API_SECRET = "1234567890"


@app.get("/")
def index():
    """
    Root endpoint that returns a welcome message.

    Returns:
        dict: A JSON object containing a greeting message.
    """
    return {"message": "Hello World!"}


@app.get("/users")
def get_user(username: str):
    """
    Endpoint to fetch user information.

    Demonstrates SQL injection vulnerability by directly interpolating user input
    into an SQL query string.

    Args:
        username (str): The username to fetch information for.

    Returns:
        dict: The SQL query string built with the given username.
    """
    query = f"SELECT * FROM users WHERE username = '{username}';"  # Vulnerable to SQL injection
    return {"query": query}


@app.get("/read_file")
def read_file(file_path: str):
    """
    Endpoint to read the contents of a file.

    The path is resolved against the allowed base directory. Absolute paths
    and paths that resolve outside the base directory are rejected.

    Args:
        file_path (str): The file path to read, relative to the base directory.

    Returns:
        dict: The contents of the file.

    Raises:
        HTTPException: 400 for a path outside the base directory, 404 if the
            file does not exist, 500 if the file cannot be read.
    """
    base_dir = get_read_file_base_dir()
    if Path(file_path).is_absolute():
        raise HTTPException(status_code=400, detail="Invalid file path")
    target = (base_dir / file_path).resolve()
    if not target.is_relative_to(base_dir):
        raise HTTPException(status_code=400, detail="Invalid file path")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        with open(target, "r", encoding="utf-8") as file:
            return {"content": file.read()}
    except (OSError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Could not read file") from exc


@app.get("/error")
def error_endpoint():
    """
    Endpoint that triggers a ZeroDivisionError.

    Demonstrates improper exception handling by allowing an unhandled exception
    to crash the application.

    Returns:
        int: The result of an erroneous division operation (never reached).
    """
    return 1 / 0  # Will cause an unhandled ZeroDivisionError


@app.post("/upload")
async def upload_file(file: Request):
    """
    Endpoint to upload a file.

    Demonstrates insecure file handling by saving the file directly without
    validation or sanitization.

    Args:
        file (Request): The file data sent in the request.

    Returns:
        dict: A message confirming successful upload.
    """
    with open("uploaded_file", "wb") as f:
        f.write(await file.body())
    return {"message": "File uploaded successfully"}


@app.get("/secure-data")
def secure_data(token: str = Query(...)):
    """
    Endpoint to access secure data.

    Demonstrates improper authentication by using a hardcoded secret and
    lack of token validation mechanisms.

    Args:
        token (str): The token provided in the query parameter.

    Returns:
        dict: The secure data if the token is valid, or an error message if not.
    """
    if token == API_SECRET:
        return {"data": "Sensitive Data"}

    return JSONResponse(status_code=403, content={"message": "Forbidden"})
