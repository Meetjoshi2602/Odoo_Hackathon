from rest_framework import serializers
from .models import User
from .logs import log_info, log_error, log_warning


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2", "terms_and_condition"]
        extra_kwargs = {"password": {"write_only": True}}

    def save(self, **kwargs):
        try:
            user = User(
                email=self.validated_data["email"],
                name=self.validated_data["name"],
                terms_and_condition=self.validated_data["terms_and_condition"],
            )
            password = self.validated_data["password"]
            password2 = self.validated_data["password2"]
            if password != password2:
                log_error("Passwords do not match during registration")
                raise serializers.ValidationError({"password": "Passwords must match."})
            user.set_password(password)
            user.save()

            return user
        except Exception as e:
            log_error(f"Error occurred during user registration: {e}")
            raise serializers.ValidationError(
                "An error occurred while registering the user."
            )


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ["email", "password"]
