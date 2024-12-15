from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

app = FastAPI()
fake_db = {"users": {}}

SECRET_KEY = "tu_clave_secreta_muy_segura"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCredentials(BaseModel):
    username: str
    password: str

class Payload(BaseModel):
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

# Implementa un sistema de autenticación con las siguientes características:
# Objetivo: Añadir un sistema de autenticación básico utilizando tokens.
# Descripción: Implementa un endpoint para la creación de usuarios y otro para el inicio de sesión. Los usuarios deben autenticarse para poder acceder a los endpoints existentes.
###
# Ruta Registro: /register
# Método: POST
# Entrada (Body): {"username": "user1", "password": "pass1"}
# Salida: {"message": "User registered successfully"}
# Status Code:
# 200: Registro exitoso
# 400: El usuario ya existe
###
# Ruta Login: /login
# Método: POST
# Entrada (Body): {"username": "user1", "password": "pass1"}
# Salida: {"access_token": <token_de_acceso>}
# Status Code:
# 200: Login Exitoso
# 401: Credenciales Inválidas

# Realiza las modificaciones necesarias en el código para implementar un cifrado de contraseñas con estas características.
# Objetivo: Mejorar la seguridad almacenando las contraseñas de manera segura.
# Descripción: Utiliza CryptContext de passlib para cifrar las contraseñas antes de guardarlas en tu base de datos simulada (fake_db).
# Status Code:
# 200: Operacion Exitosa
# 401: Credenciales Inválidas / Autorización fállida.
# Una vez registrado e iniciado sesión, se debe generar un token JWT con algoritmo HS256. Este token debe incluirse como un parámetro 
# de consulta (`query parameter`) llamado `token` en cada solicitud a los endpoints protegidos.

def verify_token(token: str = Query(None)) -> str:
    if not token:
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

@app.post("/register")
def register_user(user: UserCredentials):
    if user.username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    
    hashed_password = pwd_context.hash(user.password)
    fake_db["users"][user.username] = {
        "password": hashed_password,
        "created_at": datetime.now()
    }
    return {"message": "Registro exitoso"}

@app.post("/login")
def login(user: UserCredentials):
    if user.username not in fake_db["users"]:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    stored_user = fake_db["users"][user.username]
    if not pwd_context.verify(user.password, stored_user["password"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    token = jwt.encode(
        {
            "sub": user.username,
            "exp": datetime.now() + timedelta(hours=24)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return {"access_token": token}

# Implementa los siguientes endpoints protegidos por autenticación:
###
# Ruta: /bubble-sort
# Método: POST
# Descripción: Recibe una lista de números y devuelve la lista ordenada utilizando el algoritmo de Bubble Sort.
# Entrada: {"numbers": [lista de números]}
# Salida: {"numbers": [lista de números ordenada]}
###
# Ruta: /filter-even
# Método: POST
# Descripción: Recibe una lista de números y devuelve únicamente aquellos que son pares.
# Entrada: {"numbers": [lista de números]}
# Salida: {"even_numbers": [lista de números pares]}
###
# Ruta: /sum-elements
# Método: POST
# Descripción: Recibe una lista de números y devuelve la suma de sus elementos.
# Entrada: {"numbers": [lista de números]}
# Salida: {"sum": suma de los números}
###
# Ruta: /max-value
# Método: POST
# Descripción: Recibe una lista de números y devuelve el valor máximo.
# Entrada: {"numbers": [lista de números]}
# Salida: {"max": número máximo}
###
# Ruta: /binary-search
# Método: POST
# Descripción: Recibe un número y una lista de números ordenados. Devuelve true y el índice si el número está en la lista, de lo contrario false y -1 como index.
# Entrada: {"numbers": [lista de números], "target": int}
# Salida: {"found": booleano, "index": int}

@app.post("/bubble-sort")
def bubble_sort(payload: Payload, token: str = Query(...)):
    username = verify_token(token)
    numbers = payload.numbers.copy()
    n = len(numbers)
    for i in range(n):
        for j in range(0, n - i - 1):
            if numbers[j] > numbers[j + 1]:
                numbers[j], numbers[j + 1] = numbers[j + 1], numbers[j]
    return {"numbers": numbers}

@app.post("/filter-even")
def filter_even(payload: Payload, token: str = Query(...)):
    username = verify_token(token)
    even_numbers = [num for num in payload.numbers if num % 2 == 0]
    return {"even_numbers": even_numbers}

@app.post("/sum-elements")
def sum_elements(payload: Payload, token: str = Query(...)):
    username = verify_token(token)
    return {"sum": sum(payload.numbers)}

@app.post("/max-value")
def max_value(payload: Payload, token: str = Query(...)):
    username = verify_token(token)
    if not payload.numbers:
        raise HTTPException(status_code=400, detail="La lista está vacía")
    return {"max": max(payload.numbers)}

@app.post("/binary-search")
def binary_search(payload: BinarySearchPayload, token: str = Query(...)):
    username = verify_token(token)
    numbers = sorted(payload.numbers)
    target = payload.target
    left, right = 0, len(numbers) - 1

    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            return {"found": True, "index": mid}
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1

    return {"found": False, "index": -1}
