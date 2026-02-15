from sqlalchemy.orm import Session
from models.users import User
from sqlalchemy import func

def get_total_users(db: Session) -> int:
    return db.query(func.count(User.id)).scalar()
