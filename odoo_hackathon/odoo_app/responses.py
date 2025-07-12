from rest_framework.response import Response
from rest_framework import status


def success_response(data=None, msg="Success", total_count=None, status_code=None):
    status_code = status_code or status.HTTP_200_OK

    response = {"data": data or {}, "msg": msg, "success": True}

    if total_count is not None:
        response["total_count"] = total_count

    return Response(response, status=status_code)


def error_response(msg="Error", errors=None, status_code=None):
    status_code = status_code or status.HTTP_400_BAD_REQUEST

    return Response(
        {"data": None, "msg": msg, "success": False, "errors": errors},
        status=status_code,
    )
