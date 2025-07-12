from rest_framework.views import APIView
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from odoo_app.serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserChangePasswordSerializer,
    SendPasswordResetEmailSerializer,
    UserPasswordResetSerializer,
)
from odoo_app.renderers import UserRenderer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from .logs import log_info, log_error, log_warning
from .responses import success_response, error_response
from drf_yasg.utils import swagger_auto_schema
from .models import User
from rest_framework.exceptions import ValidationError


# Helper function used by UserRegistrationView and UserLoginView
def get_tokens_for_user(user):
    try:
        refresh = RefreshToken.for_user(user)
        access = AccessToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
    except Exception as e:
        log_error("Error generating tokens for user", e)
        raise Exception("Error generating tokens for user") from e


# --------- Registration API ------------
class UserRegistrationView(generics.GenericAPIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        try:
            serializer = UserRegistrationSerializer(data=request.data)

            if serializer.is_valid():
                user = serializer.save()
                token = get_tokens_for_user(user)
                log_info(f"User {user.name} registered successfully.")

                return success_response(
                    data={"token": token, "username": user.name},
                    msg="Registration successful",
                    status_code=status.HTTP_201_CREATED,
                )

            log_warning(f"Registration failed: {serializer.errors}")
            if "email" in serializer.errors:
                return error_response("Email already exists")
            return error_response("Invalid registration details", serializer.errors)

        except Exception as e:
            log_error("Error during registration process", e)
            return error_response(
                msg="An error occurred during registration",
                errors=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# --------- Login API ------------
class UserLoginView(generics.GenericAPIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        try:
            log_info("Login attempt received")
            serializer = UserLoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")

            # Check if user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                log_warning(f"Login failed: User with email {email} does not exist.")
                return error_response("Email or Password is not valid")

            # Check if user is active before authentication
            if not user.is_active:
                log_warning(f"Login attempt for deactivated account: {email}")
                return error_response("Your account is deactivated")

            # Authenticate user
            user = authenticate(email=email, password=password)
            if user is None:
                log_warning(f"Invalid login attempt for email: {email}")
                return error_response("Email or Password is not valid")

            # Generate token
            token = get_tokens_for_user(user)
            user_type = "admin" if user.is_admin else "user"
            log_info(
                f"User {user.id} ({user.email}) logged in successfully as {user_type}"
            )

            return success_response(
                data={
                    "token": token,
                    "useremail": user.email,
                    "userid": user.id,
                    "user_type": user_type,
                },
                msg="Login Successful",
            )

        except ValidationError as e:
            log_error(f"Validation error during login: {str(e)}")
            return error_response("Invalid input data", e.detail)

        except Exception as e:
            log_error("Unexpected error during login", exc_info=True)
            return error_response(
                "An unexpected error occurred",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# --------- Logout API ------------
class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        try:
            refresh_token = request.data.get("refresh_token")
            token = RefreshToken(refresh_token)
            token.blacklist()
            log_info(f"Logout successful for user: {request.user}")

            return Response(
                {"msg": "Logout successful", "success": True}, status=status.HTTP_200_OK
            )

        except Exception as e:
            log_error("Logout failed: %s", str(e), exc_info=True)
            return Response(
                {
                    "msg": "Logout failed",
                    "success": False,
                    "errors": {"detail": str(e)},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
