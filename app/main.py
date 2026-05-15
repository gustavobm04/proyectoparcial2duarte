from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request
)

from fastapi.security import OAuth2PasswordRequestForm

from fastapi.responses import JSONResponse

from fastapi.middleware.cors import CORSMiddleware

from sqlmodel import Session, select

from jose import jwt, JWTError

from app.database import (
    create_db_and_tables,
    get_session
)

from app.models import (
    User,
    UserCreate,
    UserResponse
)

from app.auth import (
    hash_password,
    verify_password,
    create_access_token
)

from app.config import (
    SECRET_KEY,
    ALGORITHM
)

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/")
def root():
    return {"message": "API funcionando"}


@app.post("/register", response_model=UserResponse)
def register_user(
    user_data: UserCreate,
    session: Session = Depends(get_session)
):

    existing_user = session.exec(
        select(User).where(
            User.username == user_data.username
        )
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="El nombre de usuario ya existe"
        )

    hashed_password = hash_password(
        user_data.password
    )

    new_user = User(
        full_name=user_data.full_name,
        username=user_data.username,
        hashed_password=hashed_password
    )

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return new_user


@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):

    user = session.exec(
        select(User).where(
            User.username == form_data.username
        )
    ).first()

    dummy_hash = hash_password(
        "dummy_password"
    )

    if not user:

        verify_password(
            form_data.password,
            dummy_hash
        )

        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas"
        )

    valid_password = verify_password(
        form_data.password,
        user.hashed_password
    )

    if not valid_password:
        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas"
        )

    access_token = create_access_token(
        data={"sub": user.username}
    )

    response = JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer"
        }
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=180
    )

    return response


@app.get("/users/me", response_model=UserResponse)
def get_current_user(
    request: Request,
    session: Session = Depends(get_session)
):

    token = request.cookies.get(
        "access_token"
    )

    if not token:

        auth_header = request.headers.get(
            "Authorization"
        )

        if (
            auth_header
            and auth_header.startswith("Bearer ")
        ):
            token = auth_header.split(" ")[1]

    if not token:
        raise HTTPException(
            status_code=401,
            detail="No autenticado"
        )

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:

            raise HTTPException(
                status_code=401,
                detail="Token inválido"
            )

    except JWTError:

        raise HTTPException(
            status_code=401,
            detail="Token inválido"
        )

    user = session.exec(
        select(User).where(
            User.username == username
        )
    ).first()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Usuario no encontrado"
        )

    return user