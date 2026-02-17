from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
import os

router = APIRouter()


@router.get("/media/profile_pics/{filename}", tags=["Media"])
def get_profile_pic(filename: str):
    """
    Sirve imágenes de perfil de forma segura.
    Verifica que el archivo exista y previene directory traversal.
    """
    # Validación de seguridad: el nombre no debe contener rutas (evita ../ o /)
    if filename != os.path.basename(filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Nombre de archivo inválido"
        )

    file_path = f"media/profile_pics/{filename}"

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Archivo no encontrado"
        )

    return FileResponse(file_path)
