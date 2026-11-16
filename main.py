@app.post("/api/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not pwd_context.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Forkert brugernavn eller adgangskode.")
    return {"access_token": create_token(user.username), "token_type": "bearer"}

@app.get("/api/images")
def list_images(
