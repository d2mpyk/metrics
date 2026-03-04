from datetime import datetime, timedelta
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from models.users import User
from models.clients import Client, ApprovedClient




class DashboardStatsCache:
    def __init__(self, ttl_seconds: int = 300):
        self.ttl = ttl_seconds
        self.last_updated = None
        self.data = {
            "total_users": 0, 
            "total_clients": 0,
            "total_pending": 0,
        }

    def get_stats(self, db: Session):
        now = datetime.now()
        # Si no hay datos o el tiempo de vida expiró, actualizamos desde la DB
        if self.last_updated is None or (now - self.last_updated) > timedelta(
            seconds=self.ttl
        ):
            self.data["total_users"] = (
                db.execute(select(func.count(User.id))).scalar() or 0
            )
            self.data["total_clients"] = (
                db.execute(select(func.count(Client.id))).scalar() or 0
            )
            approved = (
                db.execute(select(func.count(ApprovedClient.id))).scalar() or 0
            )
            if approved is None:
                self.data["total_pending"] = 0
            else:
                self.data["total_pending"] = approved - self.data["total_clients"]
                
            self.last_updated = now

        return self.data.copy()


# Instancia global para mantener el estado en memoria mientras la app corre
stats_cache = DashboardStatsCache(ttl_seconds=300)


def get_dashboard_stats(db: Session):
    """Obtiene estadísticas del dashboard cacheadas."""
    return stats_cache.get_stats(db)
