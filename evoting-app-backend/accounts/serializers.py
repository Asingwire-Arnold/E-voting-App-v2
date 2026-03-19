from django.conf import settings
from django.contrib.auth import get_user_model

from rest_framework import serializers
from datetime import date
from .models import User, VoterProfile, VotingStation

class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "first_name",
            "last_name",
            "full_name",
            "role",
            "password",
            "date_joined",
        ]

    def get_full_name(self, obj):
        return f"{obj.first_name or ''} {obj.last_name or ''}".strip()

class AdminListSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "full_name", "role"]

    def get_full_name(self, obj):
        return f"{obj.first_name or ''} {obj.last_name or ''}".strip()

class AdminLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class VoterRegistrationSerializer(serializers.Serializer):
    full_name = serializers.CharField()
    email = serializers.EmailField()
    national_id = serializers.CharField()
    voter_card_number = serializers.CharField()
    date_of_birth = serializers.DateField()
    station_id = serializers.IntegerField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate_date_of_birth(self, value):
        today = date.today()
        age = today.year - value.year - (
            (today.month, today.day) < (value.month, value.day)
        )

        if age < 18:
            raise serializers.ValidationError("You must be at least 18 years old.")
        return value

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        password = validated_data.pop("password")
        validated_data.pop("confirm_password")

        station_id = validated_data.pop("station_id")
        station = VotingStation.objects.get(pk=station_id)

        full_name = validated_data.pop("full_name")
        first_name, *last = full_name.split()
        last_name = " ".join(last) if last else ""

        user = User.objects.create(
            username=validated_data["national_id"],
            email=validated_data["email"],
            first_name=first_name,
            last_name=last_name,
            role=User.Role.VOTER,
        )

        user.set_password(password)
        user.save()

        VoterProfile.objects.create(
            user=user,
            station=station,
            voter_card_number=validated_data["voter_card_number"],
            date_of_birth=validated_data["date_of_birth"],
        )

        return user

class VoterListSerializer(serializers.ModelSerializer):
    voter_card_number = serializers.CharField(
        source="voter_profile.voter_card_number",
        read_only=True
    )
    station_name = serializers.CharField(
        source="voter_profile.station.name",
        read_only=True
    )

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "voter_card_number",
            "station_name",
        ]
