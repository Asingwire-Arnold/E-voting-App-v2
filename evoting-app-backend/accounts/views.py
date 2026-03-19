from django.contrib.auth import get_user_model, update_session_auth_hash
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.permissions import IsAdminUser, IsSuperAdmin
from accounts.serializers import (
    AdminCreateSerializer,
    AdminListSerializer,
    AdminLoginSerializer,
    ChangePasswordSerializer,
    UserSerializer,
    VoterListSerializer,
    VoterLoginSerializer,
    VoterProfileSerializer,
    VoterRegistrationSerializer,
)
from accounts.services import (
    AdminManagementService,
    AuthenticationService,
    VoterManagementService,
    VoterRegistrationService,
)

User = get_user_model()

class AdminLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = AdminLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = AuthenticationService()
        user, error = service.authenticate_admin(
            serializer.validated_data["username"],
            serializer.validated_data["password"],
        )

        if error:
            return Response({"detail": error}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.username,
                "full_name": user.get_full_name(),
                "role": user.role,
            },
        })


class VoterLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = VoterLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = AuthenticationService()
        user, error = service.authenticate_voter(
            serializer.validated_data["voter_card_number"],
            serializer.validated_data["password"],
        )

        if error:
            return Response({"detail": error}, status=status.HTTP_401_UNAUTHORIZED)

        # Safety check for the profile relationship
        voter_card = getattr(user, 'voter_profile', None)
        card_num = voter_card.voter_card_number if voter_card else "N/A"

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "full_name": user.get_full_name(),
                "voter_card_number": card_num,
                "role": user.role,
            },
        })


class VoterRegistrationView(APIView):
    permission_classes = [AllowAny]
    serializer_class = VoterRegistrationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = VoterRegistrationService()
        try:
            profile = service.register(serializer.validated_data)
            return Response(
                {
                    "detail": "Registration successful. Pending admin verification.",
                    "voter_card_number": profile.voter_card_number,
                },
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class VoterProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Ensure user actually has a profile (prevents 500 if an admin visits this)
        if not hasattr(request.user, 'voter_profile'):
            return Response({"detail": "Voter profile not found."}, status=status.HTTP_404_NOT_FOUND)
            
        serializer = VoterProfileSerializer(request.user.voter_profile)
        return Response(serializer.data)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not request.user.check_password(serializer.validated_data["current_password"]):
            return Response(
                {"detail": "Incorrect current password."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save()
        
        # Recommended to keep the user's session valid if using session middleware
        update_session_auth_hash(request, request.user)

        return Response({"detail": "Password changed successfully."})


class VoterListView(generics.ListAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = VoterListSerializer

    def get_queryset(self):
        service = VoterManagementService()
        return service.search(self.request.query_params)


class VoterVerifyView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        service = VoterManagementService()
        user = service.verify(pk, request.user)
        if not user:
            return Response({"detail": "Voter not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Voter verified successfully."})


class VoterVerifyAllView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        service = VoterManagementService()
        count = service.verify_all_pending(request.user)
        return Response({"detail": f"{count} voters verified."})


class VoterDeactivateView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        service = VoterManagementService()
        result = service.deactivate(pk, request.user)
        if not result:
            return Response({"detail": "Voter not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Voter deactivated."})


class AdminListView(generics.ListAPIView):
    permission_classes = [IsAdminUser]
    serializer_class = AdminListSerializer

    def get_queryset(self):
        # Added .order_by for consistent pagination and filter for roles
        return User.objects.filter(role__in=User.ADMIN_ROLES).order_by("-date_joined")


class AdminCreateView(APIView):
    permission_classes = [IsSuperAdmin]
    serializer_class = AdminCreateSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = AdminManagementService()
        try:
            admin_user = service.create_admin(serializer.validated_data, request.user)
            return Response(
                {
                    "detail": f"Admin '{admin_user.username}' created with role: {admin_user.role}",
                    "id": admin_user.id,
                },
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class AdminDeactivateView(APIView):
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk):
        if str(pk) == str(request.user.pk):
            return Response(
                {"detail": "Cannot deactivate your own account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        service = AdminManagementService()
        result = service.deactivate(pk, request.user)
        if not result:
             return Response({"detail": "Admin not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"detail": "Admin deactivated."})
