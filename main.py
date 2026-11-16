import os
import io
import uuid
import socket
import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urljoin
from typing import Optional

import httpx
from bs4 import BeautifulSoup
from PIL import Image, UnidentifiedImageError
from dotenv import load_dotenv

import jwt
from passlib.context import CryptContext
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session

load_dotenv()

# --- KONFIGURATION ---
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-skift-mig")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "jllq")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "1234")
MAX_BYTES = int(os.getenv("MAX_FILE_SIZE_MB", "15")) * 1024 * 1024

DATA_DIR = "/data" if os.path.exists("/data") or os.getenv("FLY_APP_NAME") else "."
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs("static", exist_ok=True)

ALLOWED_FORMATS = {
    "PNG": "png",
    "JPEG": "jpg",
    "WEBP": "webp",
    "GIF": "gif",
    "BMP": "bmp",
}

# --- DATABASE ---
SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'library.db')}"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class ImageRecord(Base):
    __tablename__ = "images"
    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True)
    folder = Column(String, default="Generelt", index=True)
    filename = Column(String)
    mime_type = Column(String)
    file_size = Column(Integer)
    width = Column(Integer)
    height = Column(Integer)
    is_active_wallpaper = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

# --- SIKKERHED & AUTH ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_admin():
    db = SessionLocal()
    if not db.query(User).filter(User.username == ADMIN_USERNAME).first():
        user = User(username=ADMIN_USERNAME, hashed_password=pwd_context.hash(ADMIN_PASSWORD))
        db.add(user)
        db.commit()
    db.close()

init_admin()

def create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Ugyldig token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token er udløbet eller ugyldig")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Bruger findes ikke")
    return user

# --- BILLEDEVALIDERING & SSRF-BESKYTTELSE ---
def validate_and_save_image(raw_bytes: bytes, title: str, folder: str, db: Session) -> ImageRecord:
    if len(raw_bytes) > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"Filen er for stor (maks {MAX_BYTES // (1024*1024)} MB).")
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="Filen er tom.")

    try:
        with Image.open(io.BytesIO(raw_bytes)) as img:
            img.verify()
        with Image.open(io.BytesIO(raw_bytes)) as img:
            fmt = img.format
            if fmt not in ALLOWED_FORMATS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Ikke-understøttet billedformat ({fmt}). Brug PNG, JPG, WebP, GIF eller BMP."
                )
            width, height = img.size
            ext = ALLOWED_FORMATS[fmt]
            mime_type = Image.MIME.get(fmt, f"image/{ext}")
    except UnidentifiedImageError:
        raise HTTPException(status_code=400, detail="Filen er ikke et gyldigt billede.")

    image_id = str(uuid.uuid4())
    stored_filename = f"{image_id}.{ext}"
    filepath = os.path.join(UPLOAD_DIR, stored_filename)

    with open(filepath, "wb") as f:
        f.write(raw_bytes)

    record = ImageRecord(
        id=image_id,
        title=title.strip() or f"Billede-{image_id[:6]}",
        folder=folder.strip() or "Generelt",
        filename=stored_filename,
        mime_type=mime_type,
        file_size=len(raw_bytes),
        width=width,
        height=height,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record

def check_safe_https_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Kun sikre HTTPS-links er tilladt.")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Ugyldig webadresse.")
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise HTTPException(status_code=400, detail="Lokale adresser er blokeret af sikkerhedshensyn.")

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        for info in addr_infos:
            ip_str = info[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            ):
                raise HTTPException(status_code=400, detail="Private eller interne netværksadresser er ikke tilladt.")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Kunne ikke finde serveren for det angivne link.")

async def safe_fetch_bytes(url: str) -> tuple[bytes, str, str]:
    check_safe_https_url(url)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Baggrundsbibliotek/1.0"}
    
    async with httpx.AsyncClient(follow_redirects=False, timeout=12.0) as client:
        current_url = url
        for _ in range(4):
            check_safe_https_url(current_url)
            async with client.stream("GET", current_url, headers=headers) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location")
                    if not loc:
                        raise HTTPException(status_code=400, detail="Ugyldig omdirigering fra serveren.")
                    current_url = urljoin(current_url, loc)
                    continue
                
                if resp.status_code in (401, 403):
                    raise HTTPException(
                        status_code=400,
                        detail="Siden kræver login, betalingsmur eller blokerer automatisk hentning. Download billedet til din computer og upload det i stedet."
                    )
                if resp.status_code >= 400:
                    raise HTTPException(status_code=400, detail=f"Siden svarede med fejl (HTTP {resp.status_code}).")

                content_type = resp.headers.get("content-type", "").lower()
                chunks = bytearray()
                async for chunk in resp.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > MAX_BYTES:
                        raise HTTPException(status_code=413, detail=f"Indholdet overstiger grænsen på {MAX_BYTES // (1024*1024)} MB.")
                return bytes(chunks), content_type, current_url

    raise HTTPException(status_code=400, detail="For mange omdirigeringer på linket.")

# --- FASTAPI APP & ENDPOINTS ---
app = FastAPI(title="Baggrundsbibliotek API", version="1.0.0")

class LoginRequest(BaseModel):
    username: str
    password: str

class UrlImportRequest(BaseModel):
    url: str
    title: Optional[str] = ""
    folder: Optional[str] = "Generelt"

class UpdateImageRequest(BaseModel):
    title: Optional[str] = None
    folder: Optional[str] = None
    is_active_wallpaper: Optional[bool] = None

def serialize_image(record: ImageRecord, request: Request) -> dict:
    base_url = str(request.base_url).rstrip("/")
    return {
        "id": record.id,
        "title": record.title,
        "folder": record.folder,
        "mime_type": record.mime_type,
        "file_size": record.file_size,
        "width": record.width,
        "height": record.height,
        "is_active_wallpaper": record.is_active_wallpaper,
        "created_at": record.created_at.isoformat(),
        "file_url": f"{base_url}/api/images/{record.id}/file"
    }

@app.post("/api/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not pwd_context.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Forkert brugernavn eller adgangskode.")
    return {"access_token": create_token(user.username), "token_type": "bearer"}

@app.get("/api/images")
def list_images(
    request: Request,
    q: Optional[str] = None,
    folder: Optional[str] = None,
