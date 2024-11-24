from collections import OrderedDict
from .models import Threat, Request, RequestThreat
from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate


class AddImageSerializer(serializers.Serializer):
    threat_id = serializers.IntegerField(required=True)

    def validate(self, data):
        threat_id = data.get('threat_id')

        # Дополнительная логика валидации, например проверка на существование этих id в базе данных
        if not Threat.objects.filter(pk=threat_id).exists():
            raise serializers.ValidationError(f"threat_id is incorrect")
        
        return data

class RequestSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    moderator = serializers.SerializerMethodField()

    class Meta:
        model = Request
        fields = ["pk","status","created_at","formed_at","ended_at","username","moderator","final_price"]
    def get_moderator(self, obj):
        return Request.objects.get(pk=obj.pk).moderator.username
    def get_username(self,obj):
        return Request.objects.get(pk=obj.pk).user.username

#class RequestSerializerInList(serializers.Serializer):
#    request_id = serializers.IntegerField(required=True)
#    final_price = serializers.IntegerField(required=False)
#    threats_counter = serializers.IntegerField(required=True)

class RequestSerializerInList(serializers.ModelSerializer):
    threats_amount = serializers.SerializerMethodField()
    class Meta:
        model = Request
        fields = ["pk","threats_amount"] 

    def get_threats_amount(self, obj):
        return RequestThreat.objects.filter(request_id=obj.pk).count()



class PutRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Request
        fields = ["status","created_at","formed_at","ended_at","user","moderator","final_price"]
        
class ThreatDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = ["pk","threat_name","company_name","short_description","description","status","img_url","price","detections"]

    def get_fields(self):
        new_fields = OrderedDict()
        for name, field in super().get_fields().items():
            field.required = False
            new_fields[name] = field
        return new_fields 

class ThreatListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = ["pk","threat_name","short_description","status","img_url","price"]

    def get_fields(self):
        new_fields = OrderedDict()
        for name, field in super().get_fields().items():
            field.required = False
            new_fields[name] = field
        return new_fields 

class ThreatListInRequestSerializer(serializers.ModelSerializer):
    comment = serializers.SerializerMethodField()
    class Meta:
        model = Threat
        fields = ["pk","threat_name","short_description","status","img_url","price","comment"]

    def get_comment(self, obj):
        return RequestThreat.objects.get(threat_id=obj.pk,request_id=self.context['req_id']).comment

    def get_fields(self):
        new_fields = OrderedDict()
        for name, field in super().get_fields().items():
            field.required = False
            new_fields[name] = field
        return new_fields 

class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = ["pk","img_url"]


class RequestThreatSerializer(serializers.Serializer):
    threat_id = serializers.IntegerField(required=True)
    comment = serializers.CharField(required=False)

    def validate(self, data):
        threat_id = data.get('threat_id')

        # Дополнительная логика валидации, например проверка на существование этих id в базе данных
        if not Threat.objects.filter(pk=threat_id).exists():
            raise serializers.ValidationError(f"threat_id is incorrect")

        return data
    




# AUTH SERIALIZERS

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if user is None:
            raise serializers.ValidationError("Неверные учетные данные")
        return {'user': user}
    

class CheckUsernameSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate(self, data):
        if not User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Пользователь не существует")
        
        return data
    
class AcceptRequestSerializer(serializers.Serializer):
    accept = serializers.BooleanField()