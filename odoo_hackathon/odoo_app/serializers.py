from rest_framework import serializers
from .models import User
from .logs import log_info, log_error, log_warning
from .models import Item, Swap, ItemImage


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)
    terms_and_condition = serializers.BooleanField(
        write_only=True
    )  # Add as serializer field

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2", "terms_and_condition"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, data):
        # Validate terms_and_condition
        if not data.get("terms_and_condition"):
            raise serializers.ValidationError(
                {"terms_and_condition": "You must agree to the terms and conditions."}
            )
        return data

    def save(self, **kwargs):
        try:
            user = User(
                email=self.validated_data["email"],
                name=self.validated_data["name"],
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


# User Profile Serializer
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name", "points_balance", "created_at"]


# serializers.py
class ItemImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ItemImage
        fields = ["id", "image", "uploaded_at"]


from rest_framework import serializers
from .models import Item, ItemImage
from .serializers import (
    UserProfileSerializer,
    ItemImageSerializer,
)  # Adjust imports as needed


from rest_framework import serializers
from .models import Item, ItemImage
from .serializers import (
    UserProfileSerializer,
    ItemImageSerializer,
)  # Adjust imports as needed


class ItemSerializer(serializers.ModelSerializer):
    owner = UserProfileSerializer(read_only=True)
    image = serializers.URLField(allow_null=True, required=False)
    images = ItemImageSerializer(many=True, read_only=True)

    class Meta:
        model = Item
        fields = [
            "id",
            "title",
            "description",
            "owner",
            "status",
            "image",
            "images",
            "points_value",
            "created_at",
            "updated_at",
            "category",
            "type",
            "size",
            "condition",
            "tags",
        ]

    def validate_tags(self, value):
        if value:
            tags = [tag.strip() for tag in value.split(",") if tag.strip()]
            if len(tags) > 10:
                raise serializers.ValidationError("Maximum 10 tags allowed.")
            return ",".join(tags)
        return value

    def create(self, validated_data):
        # Extract image_urls from validated_data if provided
        image_urls = validated_data.pop("image_urls", [])
        # Set the owner from the request context
        validated_data["owner"] = self.context["request"].user
        # Create the item
        item = super().create(validated_data)
        # Handle multiple image URLs if provided
        for url in image_urls:
            ItemImage.objects.create(item=item, image=url)
        return item

    def validate(self, data):
        # Ensure choices are valid (optional, for extra validation)
        for field in ["category", "type", "size", "condition"]:
            if field in data:
                choices = dict(getattr(Item, f"{field.upper()}_CHOICES", []))
                if data[field] not in choices:
                    raise serializers.ValidationError(
                        {
                            field: f"'{data[field]}' is not a valid choice. Valid choices are: {list(choices.keys())}"
                        }
                    )
        return data


class SwapSerializer(serializers.ModelSerializer):
    item_offered_id = serializers.PrimaryKeyRelatedField(
        queryset=Item.objects.all(),
        source="item_offered",
        write_only=True,
        required=False,
    )
    item_requested_id = serializers.PrimaryKeyRelatedField(
        queryset=Item.objects.all(),
        source="item_requested",
        write_only=True,
        required=False,
    )
    item_offered = ItemSerializer(read_only=True)
    item_requested = ItemSerializer(read_only=True)
    requester = UserProfileSerializer(read_only=True)

    class Meta:
        model = Swap
        fields = [
            "id",
            "requester",
            "item_offered",
            "item_offered_id",
            "item_requested",
            "item_requested_id",
            "status",
            "created_at",
            "updated_at",
        ]

    def validate(self, data):
        item_offered = data.get(
            "item_offered", self.instance.item_offered if self.instance else None
        )
        item_requested = data.get(
            "item_requested", self.instance.item_requested if self.instance else None
        )
        request = self.context.get("request")

        # Only validate item fields if they are provided (for updates)
        if item_offered and item_requested:
            # Ensure items are available
            if (
                item_offered.status != "available"
                or item_requested.status != "available"
            ):
                raise serializers.ValidationError(
                    "One or both items are not available for swapping."
                )

            # Ensure user doesn't request their own item
            if item_offered.owner == item_requested.owner:
                raise serializers.ValidationError("You cannot swap your own items.")

            # Ensure the requester is the owner of the offered item
            if item_offered.owner != request.user:
                raise serializers.ValidationError("You can only offer items you own.")

        return data

    def create(self, validated_data):
        validated_data["requester"] = self.context["request"].user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Update only the fields provided
        if "item_offered" in validated_data:
            instance.item_offered = validated_data["item_offered"]
        if "item_requested" in validated_data:
            instance.item_requested = validated_data["item_requested"]
        if "status" in validated_data:
            instance.status = validated_data["status"]
        instance.save()
        return instance
