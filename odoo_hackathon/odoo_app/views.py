from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db.models import Q
from django.db import transaction
from .models import User, Item, Swap
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    ItemSerializer,
    SwapSerializer,
)
from .renderers import UserRenderer
from .logs import log_info, log_error, log_warning
from .responses import success_response, error_response
from .logs import log_info, log_error, log_warning


def get_tokens_for_user(user):
    try:
        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
    except Exception as e:
        log_error(f"Error generating tokens for user {user.email}", exc_info=True)
        raise Exception("Error generating tokens for user") from e


class UserRegistrationView(generics.GenericAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        try:
            serializer = UserRegistrationSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                token = get_tokens_for_user(user)

                return success_response(
                    data={"token": token, "username": user.name},
                    msg="Registration successful",
                    status_code=status.HTTP_201_CREATED,
                )

            if "email" in serializer.errors:
                return error_response("Email already exists")
            return error_response("Invalid registration details", serializer.errors)
        except Exception as e:
            return error_response(
                msg="An error occurred during registration",
                errors=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserLoginView(generics.GenericAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        try:
            log_info("Login attempt received")
            serializer = UserLoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                log_warning(f"Login failed: User with email {email} does not exist.")
                return error_response("Email or Password is not valid")

            if not user.is_active:
                log_warning(f"Login attempt for deactivated account: {email}")
                return error_response("Your account is deactivated")

            user = authenticate(email=email, password=password)
            if user is None:
                log_warning(f"Invalid login attempt for email: {email}")
                return error_response("Email or Password is not valid")

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
            log_error(f"Unexpected error during login: {e}", exc_info=True)
            return error_response(
                "An unexpected error occurred",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                log_warning(
                    f"Logout failed for user {request.user.email}: No refresh token provided"
                )
                return error_response("Refresh token is required")
            token = RefreshToken(refresh_token)
            token.blacklist()
            log_info(f"Logout successful for user: {request.user.email}")
            return success_response(msg="Logout successful")
        except Exception as e:
            log_error(
                f"Logout failed for user {request.user.email}: {str(e)}", exc_info=True
            )
            return error_response(
                "Logout failed", str(e), status_code=status.HTTP_400_BAD_REQUEST
            )


class FeaturedItemsView(generics.ListAPIView):
    queryset = Item.objects.filter(
        status="available", approval_status="approved"
    ).order_by("-created_at")[:5]
    serializer_class = ItemSerializer
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        try:
            log_info("Fetching featured items for landing page")
            serializer = self.get_serializer(self.get_queryset(), many=True)
            return success_response(
                data=serializer.data, msg="Featured items retrieved successfully"
            )
        except Exception as e:
            log_error(f"Error fetching featured items: {e}", exc_info=True)
            return error_response("Failed to fetch featured items", str(e))


class UserDashboardView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get(self, request, *args, **kwargs):
        try:
            log_info(f"Fetching dashboard for user {request.user.id}")
            user_serializer = UserProfileSerializer(request.user)
            user_items = Item.objects.filter(owner=request.user)
            items_serializer = ItemSerializer(user_items, many=True)
            ongoing_swaps = Swap.objects.filter(
                Q(requester=request.user)
                | Q(item_offered__owner=request.user)
                | Q(item_requested__owner=request.user),
                status__in=["pending", "accepted"],
            )
            completed_swaps = Swap.objects.filter(
                Q(requester=request.user)
                | Q(item_offered__owner=request.user)
                | Q(item_requested__owner=request.user),
                status="completed",
            )
            ongoing_swaps_serializer = SwapSerializer(ongoing_swaps, many=True)
            completed_swaps_serializer = SwapSerializer(completed_swaps, many=True)

            data = {
                "profile": user_serializer.data,
                "items": items_serializer.data,
                "ongoing_swaps": ongoing_swaps_serializer.data,
                "completed_swaps": completed_swaps_serializer.data,
            }
            return success_response(
                data=data, msg="Dashboard data retrieved successfully"
            )
        except Exception as e:
            log_error(
                f"Error fetching dashboard for user {request.user.id}: {e}",
                exc_info=True,
            )
            return error_response("Failed to fetch dashboard data", str(e))


class ItemCreateView(generics.CreateAPIView):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            log_info(f"Item creation attempt by user {request.user.id}")
            data = request.data
            created_items = []

            if isinstance(data, list):
                for item_data in data:
                    if not isinstance(item_data, dict):
                        log_warning(f"Invalid item data format: {item_data}")
                        return error_response(
                            "Each item in the list must be a dictionary",
                            status_code=status.HTTP_400_BAD_REQUEST,
                        )
                    serializer = self.get_serializer(
                        data=item_data, context={"request": request}
                    )
                    if serializer.is_valid():
                        item = serializer.save()
                        created_items.append(serializer.data)
                    else:
                        log_warning(f"Item creation failed: {serializer.errors}")
                        return error_response(
                            f"Failed to create item: {item_data.get('title', 'Unknown')}",
                            serializer.errors,
                            status_code=status.HTTP_400_BAD_REQUEST,
                        )
                log_info(
                    f"Successfully created {len(created_items)} items for user {request.user.id}"
                )
                return success_response(
                    data=created_items,
                    msg=f"Successfully created {len(created_items)} items",
                    status_code=status.HTTP_201_CREATED,
                )
            else:
                if not isinstance(data, dict):
                    log_warning(f"Invalid data format: {data}")
                    return error_response(
                        "Request data must be a dictionary",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )
                serializer = self.get_serializer(
                    data=data, context={"request": request}
                )
                if serializer.is_valid():
                    item = serializer.save()
                    created_items.append(serializer.data)
                    log_info(
                        f"Successfully created item: {item.title} for user {request.user.id}"
                    )
                    return success_response(
                        data=serializer.data,
                        msg="Item created successfully",
                        status_code=status.HTTP_201_CREATED,
                    )
                log_warning(f"Item creation failed: {serializer.errors}")
                return error_response("Failed to create item", serializer.errors)

        except Exception as e:
            log_error(
                f"Error creating item(s) for user {request.user.id}: {str(e)}",
                exc_info=True,
            )
            return error_response(
                "An unexpected error occurred",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    permission_classes = [AllowAny]

    def get_permissions(self):
        if self.request.method in ["PUT", "DELETE"]:
            return [IsAuthenticated()]
        return [AllowAny()]

    def get(self, request, *args, **kwargs):
        try:
            log_info(f"Fetching item details for item ID {self.kwargs['pk']}")
            item = self.get_object()
            serializer = self.get_serializer(item)
            return success_response(
                data=serializer.data, msg="Item details retrieved successfully"
            )
        except Item.DoesNotExist:
            log_warning(f"Item ID {self.kwargs['pk']} not found")
            return error_response(
                "Item not found", status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            log_error(f"Error fetching item details: {str(e)}", exc_info=True)
            return error_response(
                "Failed to fetch item details",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def put(self, request, *args, **kwargs):
        try:
            log_info(
                f"Item update attempt for item ID {self.kwargs['pk']} by user {request.user.id}"
            )
            item = self.get_object()
            if item.owner != request.user:
                log_warning(
                    f"User {request.user.id} attempted to update item {self.kwargs['pk']} they do not own"
                )
                return error_response(
                    "You can only update your own items",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            serializer = self.get_serializer(item, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                log_info(
                    f"Successfully updated item: {item.title} for user {request.user.id}"
                )
                return success_response(
                    data=serializer.data,
                    msg="Item updated successfully",
                    status_code=status.HTTP_200_OK,
                )
            log_warning(f"Item update failed: {serializer.errors}")
            return error_response(
                "Failed to update item",
                serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        except Item.DoesNotExist:
            log_warning(f"Item ID {self.kwargs['pk']} not found")
            return error_response(
                "Item not found", status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            log_error(
                f"Error updating item {self.kwargs['pk']}: {str(e)}", exc_info=True
            )
            return error_response(
                "Failed to update item",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def delete(self, request, *args, **kwargs):
        try:
            log_info(
                f"Item deletion attempt for item ID {self.kwargs['pk']} by user {request.user.id}"
            )
            item = self.get_object()
            if item.owner != request.user and not request.user.is_admin:
                log_warning(
                    f"User {request.user.id} attempted to delete item {self.kwargs['pk']} they do not own"
                )
                return error_response(
                    "You can only delete your own items or must be an admin",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            item_title = item.title
            item.delete()
            log_info(
                f"Successfully deleted item: {item_title} for user {request.user.id}"
            )
            return success_response(
                msg="Item deleted successfully", status_code=status.HTTP_204_NO_CONTENT
            )
        except Item.DoesNotExist:
            log_warning(f"Item ID {self.kwargs['pk']} not found")
            return error_response(
                "Item not found", status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            log_error(
                f"Error deleting item {self.kwargs['pk']}: {str(e)}", exc_info=True
            )
            return error_response(
                "Failed to delete item",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ItemListView(generics.ListAPIView):
    serializer_class = ItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Filter items by the authenticated user only
        return Item.objects.filter(owner=self.request.user)

    def get(self, request, *args, **kwargs):
        try:
            log_info(f"Fetching all items for user {request.user.id}")
            serializer = self.get_serializer(self.get_queryset(), many=True)
            return success_response(
                data=serializer.data, msg="Items retrieved successfully"
            )
        except Exception as e:
            log_error(
                f"Error fetching items for user {request.user.id}: {str(e)}",
                exc_info=True,
            )
            return error_response(
                "Failed to fetch items",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RedeemItemView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ItemSerializer

    def post(self, request, *args, **kwargs):
        try:
            item_id = request.data.get("item_id")
            if not item_id:
                log_warning(
                    f"User {request.user.id} attempted to redeem without item_id"
                )
                return error_response(
                    "Item ID is required", status_code=status.HTTP_400_BAD_REQUEST
                )

            item = Item.objects.get(id=item_id)
            if item.status != "available" or item.approval_status != "approved":
                log_warning(
                    f"User {request.user.id} attempted to redeem unavailable or unapproved item {item_id}"
                )
                return error_response(
                    "Item is not available or not approved",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )

            if item.owner == request.user:
                log_warning(
                    f"User {request.user.id} attempted to redeem their own item {item_id}"
                )
                return error_response(
                    "You cannot redeem your own item",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )

            if request.user.points_balance < item.points_value:
                log_warning(
                    f"User {request.user.id} has insufficient points for item {item_id}"
                )
                return error_response(
                    "Insufficient points", status_code=status.HTTP_400_BAD_REQUEST
                )

            with transaction.atomic():
                request.user.points_balance -= item.points_value
                item.owner.points_balance += item.points_value
                item.status = "swapped"
                item.owner = request.user
                request.user.save()
                item.owner.save()
                item.save()

            log_info(
                f"User {request.user.id} redeemed item {item.title} for {item.points_value} points"
            )
            return success_response(
                data=ItemSerializer(item).data,
                msg="Item redeemed successfully",
                status_code=status.HTTP_200_OK,
            )
        except Item.DoesNotExist:
            log_warning(f"Item ID {item_id} not found for redemption")
            return error_response(
                "Item not found", status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            log_error(
                f"Error redeeming item for user {request.user.id}: {str(e)}",
                exc_info=True,
            )
            return error_response(
                "Failed to redeem item",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SwapRequestView(generics.CreateAPIView):
    queryset = Swap.objects.all()
    serializer_class = SwapSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            log_info(f"Swap request attempt by user {request.user.id}")
            serializer = self.get_serializer(
                data=request.data, context={"request": request}
            )
            if serializer.is_valid():
                serializer.save()
                return success_response(
                    data=serializer.data,
                    msg="Swap request created successfully",
                    status_code=status.HTTP_201_CREATED,
                )
            log_warning(f"Swap request failed: {serializer.errors}")
            return error_response("Failed to create swap request", serializer.errors)
        except Exception as e:
            log_error(
                f"Error creating swap request for user {request.user.id}: {e}",
                exc_info=True,
            )
            return error_response("An unexpected error occurred", str(e))


class SwapUpdateView(generics.UpdateAPIView):
    queryset = Swap.objects.all()
    serializer_class = SwapSerializer
    permission_classes = [IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        try:
            swap = self.get_object()
            is_requester = swap.requester == request.user
            is_requested_owner = swap.item_requested.owner == request.user

            if not (is_requester or is_requested_owner):
                log_warning(
                    f"User {request.user.email} attempted to update swap {swap.id} they are not authorized for"
                )
                return error_response(
                    "You are not authorized to update this swap",
                    status_code=status.HTTP_403_FORBIDDEN,
                )

            if is_requester:
                allowed_fields = {"item_offered_id", "item_requested_id"}
                if any(key not in allowed_fields for key in request.data.keys()):
                    log_warning(
                        f"Requester {request.user.email} attempted to update unauthorized fields in swap {swap.id}"
                    )
                    return error_response(
                        "Requesters can only update item_offered_id or item_requested_id",
                        status_code=status.HTTP_403_FORBIDDEN,
                    )
            elif is_requested_owner:
                allowed_fields = {"status"}
                if any(key not in allowed_fields for key in request.data.keys()):
                    log_warning(
                        f"Requested item owner {request.user.email} attempted to update unauthorized fields in swap {swap.id}"
                    )
                    return error_response(
                        "Requested item owners can only update status",
                        status_code=status.HTTP_403_FORBIDDEN,
                    )

            serializer = self.get_serializer(
                swap, data=request.data, partial=True, context={"request": request}
            )
            if serializer.is_valid():
                serializer.save()
                log_info(
                    f"Swap {swap.id} updated to status {serializer.validated_data.get('status', swap.status)} by user {request.user.email}"
                )

                if serializer.validated_data.get("status") == "completed":
                    if not is_requested_owner:
                        log_warning(
                            f"User {request.user.email} attempted to complete swap {swap.id} without being the requested item owner"
                        )
                        return error_response(
                            "Only the requested item owner can complete the swap",
                            status_code=status.HTTP_403_FORBIDDEN,
                        )
                    if (
                        swap.item_requested.points_value is None
                        or swap.item_requested.points_value <= 0
                    ):
                        log_error(
                            f"Invalid points_value for item {swap.item_requested.id}: {swap.item_requested.points_value}"
                        )
                        return error_response(
                            "Requested item has invalid points value",
                            status_code=status.HTTP_400_BAD_REQUEST,
                        )

                    with transaction.atomic():
                        original_offered_owner = swap.item_offered.owner
                        original_requested_owner = swap.item_requested.owner

                        swap.item_offered.owner = original_requested_owner
                        swap.item_requested.owner = swap.requester

                        swap.item_offered.status = "swapped"
                        swap.item_requested.status = "swapped"

                        swap.item_offered.save()
                        swap.item_requested.save()

                        original_requested_owner.points_balance += (
                            swap.item_requested.points_value
                        )
                        original_requested_owner.save()

                        log_info(
                            f"Swap {swap.id} completed: "
                            f"Item {swap.item_offered.title} ownership transferred from {original_offered_owner.email} to {swap.item_offered.owner.email}; "
                            f"Item {swap.item_requested.title} ownership transferred from {original_requested_owner.email} to {swap.item_requested.owner.email}; "
                            f"{swap.item_requested.points_value} points awarded to user {original_requested_owner.email}"
                        )

                return success_response(
                    data=serializer.data, msg="Swap updated successfully"
                )
            log_warning(f"Swap update failed: {serializer.errors}")
            return error_response("Failed to update swap", serializer.errors)
        except Exception as e:
            log_error(
                f"Error updating swap {swap.id} for user {request.user.id}: {e}",
                exc_info=True,
            )
            return error_response(
                "An unexpected error occurred",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AdminItemModerationView(generics.UpdateAPIView):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    permission_classes = [IsAdminUser]

    def patch(self, request, *args, **kwargs):
        try:
            item = self.get_object()
            serializer = self.get_serializer(
                item, data=request.data, partial=True, context={"request": request}
            )
            if serializer.is_valid():
                approval_status = serializer.validated_data.get("approval_status")
                if approval_status not in ["approved", "rejected"]:
                    log_warning(
                        f"Invalid approval status {approval_status} for item {item.id} by admin {request.user.email}"
                    )
                    return error_response(
                        "Approval status must be 'approved' or 'rejected'",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )
                if approval_status == "approved" and item.status == "pending":
                    item.status = "available"
                elif approval_status == "rejected":
                    item.status = "pending"  # Keep status as pending for rejected items
                serializer.save()
                log_info(
                    f"Item {item.id} {approval_status} by admin {request.user.email}"
                )
                return success_response(
                    data=serializer.data,
                    msg=f"Item {approval_status} successfully",
                    status_code=status.HTTP_200_OK,
                )
            log_warning(f"Item moderation failed: {serializer.errors}")
            return error_response(
                "Failed to moderate item",
                serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        except Item.DoesNotExist:
            log_warning(f"Item ID {self.kwargs['pk']} not found for moderation")
            return error_response(
                "Item not found", status_code=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            log_error(
                f"Error moderating item {self.kwargs['pk']} by admin {request.user.id}: {str(e)}",
                exc_info=True,
            )
            return error_response(
                "Failed to moderate item",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AdminItemListView(generics.ListAPIView):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    permission_classes = [IsAdminUser]

    def get(self, request, *args, **kwargs):
        try:
            log_info(f"Admin {request.user.id} fetching all items for moderation")
            serializer = self.get_serializer(self.get_queryset(), many=True)
            return success_response(
                data=serializer.data, msg="Items retrieved successfully for admin"
            )
        except Exception as e:
            log_error(
                f"Error fetching items for admin {request.user.id}: {str(e)}",
                exc_info=True,
            )
            return error_response(
                "Failed to fetch items",
                str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
