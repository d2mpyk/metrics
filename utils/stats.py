from datetime import datetime, timedelta, UTC
from sqlalchemy import func, select, and_
from sqlalchemy.orm import Session
from models.users import User
from models.clients import Client, ApprovedClient, ServerMetric


class DashboardStatsCache:
    def __init__(self, ttl_seconds: int = 120):
        self.ttl = ttl_seconds
        self.last_updated = None
        self.data = {
            "total_users": 0,
            "total_clients": 0,
            "total_pending": 0,
            "total_errors": 0,
        }

    def get_stats(self, db: Session):
        now = datetime.now(UTC)
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
            self.data["total_pending"] = (
                db.execute(
                    select(func.count(ApprovedClient.id)).where(
                        ApprovedClient.is_active == False
                    )
                ).scalar()
                or 0
            )

            # Calcular dispositivos con error (Sin métricas o última métrica > 2 min)
            threshold = now - timedelta(seconds=130)

            # Subconsulta para obtener el ID de clientes con métricas recientes
            subq = (
                select(ServerMetric.client_id)
                .where(ServerMetric.timestamp >= threshold)
                .distinct()
                .subquery()
            )

            # Contamos los clientes que NO están en esa subconsulta (están offline/error)
            # pero que están marcados como activos en el sistema.
            self.data["total_errors"] = (
                db.execute(
                    select(func.count(Client.id)).where(
                        and_(Client.is_active == True, Client.id.not_in(select(subq)))
                    )
                ).scalar()
                or 0
            )

            self.last_updated = now

        return self.data.copy()


# Instancia global para mantener el estado en memoria mientras la app corre
stats_cache = DashboardStatsCache(ttl_seconds=60)


def get_dashboard_stats(db: Session):
    """Obtiene estadísticas del dashboard cacheadas."""
    return stats_cache.get_stats(db)
