import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from models.clients import ServerMetric, Client
from models.users import User
from utils.stats import calculate_network_speed, DashboardStatsCache

# -----------------------------------------------------------------------------
# TESTS DE UTILIDADES (UNIT TESTS)
# -----------------------------------------------------------------------------


def test_calculate_network_speed_first_metric():
    """Verifica que la velocidad sea 0 si no hay métrica anterior."""
    speed_sent, speed_recv = calculate_network_speed(
        last_metric=None,
        new_net_sent=1000,
        new_net_recv=2000,
        current_timestamp=datetime.now(timezone.utc),
    )
    assert speed_sent == 0.0
    assert speed_recv == 0.0


def test_calculate_network_speed_normal_case():
    """Verifica el cálculo de velocidad en un caso normal."""
    now = datetime.now(timezone.utc)
    last_ts = now - timedelta(seconds=2)
    last_metric = ServerMetric(timestamp=last_ts, net_sent=1000, net_recv=2000)

    speed_sent, speed_recv = calculate_network_speed(
        last_metric=last_metric,
        new_net_sent=3000,  # +2000 bytes
        new_net_recv=6000,  # +4000 bytes
        current_timestamp=now,
    )
    # 2000 bytes / 2 seconds = 1000 B/s
    assert speed_sent == pytest.approx(1000.0)
    # 4000 bytes / 2 seconds = 2000 B/s
    assert speed_recv == pytest.approx(2000.0)


def test_calculate_network_speed_counter_reset():
    """Verifica que la velocidad sea 0 si el contador se reinicia (nuevo valor < viejo)."""
    now = datetime.now(timezone.utc)
    last_ts = now - timedelta(seconds=2)
    last_metric = ServerMetric(timestamp=last_ts, net_sent=5000, net_recv=5000)

    speed_sent, speed_recv = calculate_network_speed(
        last_metric=last_metric,
        new_net_sent=1000,  # Reinicio
        new_net_recv=6000,  # Normal
        current_timestamp=now,
    )
    assert speed_sent == 0.0  # No debe ser negativo
    assert speed_recv == pytest.approx(500.0)  # (6000-5000)/2


def test_calculate_network_speed_no_time_delta():
    """Verifica que la velocidad sea 0 si no ha pasado tiempo."""
    now = datetime.now(timezone.utc)
    last_metric = ServerMetric(timestamp=now, net_sent=1000, net_recv=2000)

    speed_sent, speed_recv = calculate_network_speed(
        last_metric=last_metric,
        new_net_sent=3000,
        new_net_recv=6000,
        current_timestamp=now,
    )
    assert speed_sent == 0.0
    assert speed_recv == 0.0


def test_calculate_network_speed_missing_new_data():
    """Verifica que la velocidad sea 0 si faltan los nuevos datos de red."""
    now = datetime.now(timezone.utc)
    last_ts = now - timedelta(seconds=2)
    last_metric = ServerMetric(timestamp=last_ts, net_sent=1000, net_recv=2000)

    speed_sent, speed_recv = calculate_network_speed(
        last_metric=last_metric,
        new_net_sent=None,
        new_net_recv=6000,
        current_timestamp=now,
    )
    assert speed_sent == 0.0
    assert speed_recv == 0.0


def test_calculate_network_speed_with_naive_datetime():
    """Verifica que la función maneje timestamps sin timezone (naive)."""
    now_aware = datetime.now(timezone.utc)
    # Simulamos un timestamp 'naive' como podría venir de una DB mal configurada
    last_ts_naive = now_aware.replace(tzinfo=None) - timedelta(seconds=2)
    last_metric = ServerMetric(timestamp=last_ts_naive, net_sent=1000, net_recv=2000)

    speed_sent, speed_recv = calculate_network_speed(
        last_metric=last_metric,
        new_net_sent=3000,
        new_net_recv=6000,
        current_timestamp=now_aware,
    )
    assert speed_sent == pytest.approx(1000.0)
    assert speed_recv == pytest.approx(2000.0)


def test_dashboard_stats_cache_logic(db_session):
    """
    Verifica que el caché de estadísticas del dashboard funcione correctamente,
    respetando el TTL (Time-To-Live).
    """
    # 1. Setup: Usar una instancia de caché fresca con un TTL corto para la prueba
    cache = DashboardStatsCache(ttl_seconds=10)

    # 2. Poblar la DB con datos iniciales
    db_session.add(
        User(
            username="test_user",
            email="test@test.com",
            password_hash="...",
            role="user",
        )
    )
    db_session.add(
        Client(client_identifier="c1", client_secret_key="s1", ip_address="1.1.1.1")
    )
    db_session.commit()

    # 3. "Espiar" la ejecución de la DB para contar las consultas
    with patch.object(db_session, "execute", wraps=db_session.execute) as spy_execute:
        # --- Primera llamada: debe consultar la base de datos ---
        stats1 = cache.get_stats(db_session)
        assert stats1["total_users"] == 1
        assert stats1["total_clients"] == 1
        assert spy_execute.call_count > 0  # Se hicieron consultas

        calls_after_first_request = spy_execute.call_count

        # --- Segunda llamada (dentro del TTL): debe devolver datos de la caché ---
        stats2 = cache.get_stats(db_session)
        assert stats2 == stats1  # Los datos deben ser idénticos
        # El número de llamadas a la DB NO debe haber aumentado
        assert spy_execute.call_count == calls_after_first_request

        # --- Tercera llamada (después del TTL): debe consultar la DB de nuevo ---
        # Mockeamos datetime.now() dentro del módulo 'utils.stats' para simular el paso del tiempo
        with patch("utils.stats.datetime") as mock_datetime:
            # Simulamos que han pasado 11 segundos desde la última actualización
            mock_datetime.now.return_value = cache.last_updated + timedelta(seconds=11)

            # Añadimos un nuevo usuario para ver si las estadísticas se actualizan
            db_session.add(
                User(
                    username="user2",
                    email="u2@test.com",
                    password_hash="...",
                    role="user",
                )
            )
            db_session.commit()

            stats3 = cache.get_stats(db_session)
            assert stats3["total_users"] == 2  # Las estadísticas se actualizaron
            assert spy_execute.call_count > calls_after_first_request

            calls_after_ttl_request = spy_execute.call_count

            # --- Cuarta llamada (dentro del nuevo TTL): debe estar en caché de nuevo ---
            stats4 = cache.get_stats(db_session)
            assert stats4 == stats3
            assert spy_execute.call_count == calls_after_ttl_request
