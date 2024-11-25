from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework import status
from .serializers import *
from .models import Request, Threat, RequestThreat
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.contrib.auth import logout
from django.contrib.auth import login
from datetime import datetime 

from django.conf import settings
from minio import Minio
from django.core.files.uploadedfile import InMemoryUploadedFile

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

from rest_framework.decorators import authentication_classes
from rest_framework.authentication import SessionAuthentication, BasicAuthentication

class ThreatList(APIView):
    model_class = Threat
    serializer_class = ThreatListSerializer
    
    # получить список угроз
    @swagger_auto_schema(
        operation_description="Get a list of threats. Optionally filter by price range using 'price_from' and 'price_to'.",
        manual_parameters=[
            openapi.Parameter('price_from', openapi.IN_QUERY, description="Minimum price of threat", type=openapi.TYPE_NUMBER),
            openapi.Parameter('price_to', openapi.IN_QUERY, description="Maximum price of threat", type=openapi.TYPE_NUMBER)
        ],
        responses={200: ThreatListSerializer(many=True)}
    )

    def get(self, request):
        if 'price_from' in request.GET and 'price_to' in request.GET:
            threats = self.model_class.objects.filter(price__lte=request.GET['price_to'],price__gte=request.GET['price_from'])
            if 'name' in request.GET:
                threats = threats.filter(threat_name__icontains=request.GET['name'])
        elif 'name' in request.GET:
            threats = self.model_class.objects.filter(threat_name__icontains=request.GET['name'])
        else:
            threats = self.model_class.objects.all()

        
        serializer = self.serializer_class(threats, many=True)
        resp = serializer.data
        draft_request = False

        if request.user.is_authenticated:
            draft_request = Request.objects.filter(user=request.user, status='draft').first()
        if draft_request:
            request_serializer = RequestSerializerInList(draft_request)  # Use RequestSerializer here
            resp.append({'request': request_serializer.data})
        else:
            resp.append({'request': {'threats_amount':0}})

        return Response(resp,status=status.HTTP_200_OK)


class AddNewThreatView(APIView):
    model_class = Threat
    serializer_class = ThreatDetailSerializer

     # добавить новую угрозу (для модератора)
    @swagger_auto_schema(
        operation_description="Add a new threat (moderators only).",
        request_body=ThreatDetailSerializer,
        responses={201: ThreatDetailSerializer(), 400: 'Bad Request'}
    )
    def post(self, request, format=None):

        if not request.user.is_staff:
            return Response(status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ThreatDetail(APIView):
    model_class = Threat
    serializer_class = ThreatDetailSerializer

    # получить описание угрозы
    @swagger_auto_schema(
        operation_description="Get details of a specific threat by ID.",
        responses={200: ThreatDetailSerializer()}
    )
    def get(self, request, pk):
        threat = get_object_or_404(self.model_class, pk=pk)
        serializer = self.serializer_class(threat)
        return Response(serializer.data)
    

    @swagger_auto_schema(
        operation_description="Delete a threat by ID (moderators only).",
        responses={204: 'No Content', 403: 'Forbidden'}
    )
    # удалить угрозу (для модератора)
    def delete(self, request, pk):

        if not request.user.is_staff:
            return Response(status=status.HTTP_403_FORBIDDEN)

        threat = get_object_or_404(self.model_class, pk=pk)
        threat.status = 'deleted'
        threat.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    # обновление угрозы (для модератора)
    @swagger_auto_schema(
        operation_description="Update a threat (moderators only).",
        request_body=ThreatDetailSerializer,
        responses={200: ThreatDetailSerializer(), 400: 'Bad Request'}
    )
    def put(self, request, pk, format=None):

        if not request.user.is_staff:
            return Response(status=status.HTTP_403_FORBIDDEN)

        threat = get_object_or_404(self.model_class, pk=pk)
        serializer = self.serializer_class(threat, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
class AddThreatView(APIView):

    permission_classes = [IsAuthenticated]

    # добавление услуги в заявку
    @swagger_auto_schema(
        operation_description="Add a threat to a user's draft request. Creates a new request if no draft exists.",
        responses={200: "Threat successfully added to the request", 404: "Threat not found"},
        manual_parameters=[
            openapi.Parameter('pk', openapi.IN_PATH, description="Primary key of the threat", type=openapi.TYPE_INTEGER, required=True)
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={'price': openapi.Schema(type=openapi.TYPE_NUMBER, description='Price of the threat', example=100.00)},
            required=[]
        )
    )
    def post(self, request, pk):
        # создаем заявку, если ее еще нет
        if not Request.objects.filter(user=request.user,status='draft').exists():
            new_req = Request()
            new_req.user = request.user
            new_req.save()
            
        # получаем id заявки
        request_id = Request.objects.filter(user=request.user,status='draft').first().pk
        if Threat.objects.filter(pk=pk).exists():
            threat = Threat.objects.get(pk=pk)
            new_req_threat = RequestThreat()
            new_req_threat.threat_id = pk
            new_req_threat.request_id = request_id
            new_req_threat.price = threat.price
            if 'price' in request.data:
                new_req_threat.price = request.data["price"]
            new_req_threat.save()
            return Response(status=status.HTTP_200_OK)
        else:
            return Response({'error':'threat not found'}, status=status.HTTP_404_NOT_FOUND)
        


class ImageView(APIView):
    
    def process_file_upload(self, file_object: InMemoryUploadedFile, client, image_name):
        try:
            client.put_object('static', image_name, file_object, file_object.size)
            return f"http://localhost:9000/static/{image_name}"
        except Exception as e:
            return {"error": str(e)}

    def add_pic(self, threat, pic):
        client = Minio(           
                endpoint=settings.AWS_S3_ENDPOINT_URL,
            access_key=settings.AWS_ACCESS_KEY_ID,
            secret_key=settings.AWS_SECRET_ACCESS_KEY,
            secure=settings.MINIO_USE_SSL
        )
        i = threat.id
        img_obj_name = f"{i}.png"

        if not pic:
            return Response({"error": "Нет файла для изображения логотипа."})
        result = self.process_file_upload(pic, client, img_obj_name)

        if 'error' in result:
            return Response(result)

        threat.img_url = result
        threat.save()

        return Response({"message": "success"})

    @swagger_auto_schema(
        operation_description="Upload an image for a specific threat.",
        request_body=AddImageSerializer,
        responses={201: "Image uploaded successfully", 400: "Bad request"}
    )
    def post(self, request):

        if not request.user.is_staff:
            return Response(status=status.HTTP_403_FORBIDDEN)
        
        serializer = AddImageSerializer(data=request.data)
        if serializer.is_valid():
            threat = Threat.objects.get(pk=serializer.validated_data['threat_id'])
            pic = request.FILES.get("pic")
            pic_result = self.add_pic(threat, pic)
            # Если в результате вызова add_pic результат - ошибка, возвращаем его.
            if 'error' in pic_result.data:    
                return pic_result
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    
# Личный кабинет (обновление профиля)
class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update the profile of the authenticated user.",
        request_body=UserUpdateSerializer,
        responses={200: UserUpdateSerializer(), 400: "Bad request"}
    )
    def put(self, request):
        serializer = UserUpdateSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            if 'password' in request.data:
                request.user.set_password(request.data['password'])
            if 'email' in request.data:
                request.user.email = request.data['email']
            request.user.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserRegistrationView(APIView):
    @swagger_auto_schema(
        operation_description="Register a new user.",
        request_body=UserRegistrationSerializer,
        responses={201: "User registered successfully", 400: "Bad request"}
    )
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    @swagger_auto_schema(
        operation_description="Authenticate a user with username and password. Returns session cookie upon success.",
        request_body=AuthTokenSerializer,
        responses={200: "Login successful", 400: "Invalid credentials"}
    )
    def post(self, request):
        serializer = AuthTokenSerializer(data=request.data)
        if serializer.is_valid():
            username = request.data['username']
            password = request.data['password']
            if request.user is not None:
                logout(request)
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)  # Сохраняем информацию о пользователе в сессии
                if user.is_staff:
                    return Response({'message': 'Login successful','staff':True}, status=status.HTTP_200_OK)
                return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Логаут
class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Logout the authenticated user. Removes the session.",
        responses={204: "Logout successful"}
    )
    def post(self, request):
        logout(request)  # Удаляем сессию
        return Response({'message': 'Logout successful'}, status=status.HTTP_204_NO_CONTENT)


class ListRequests(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get a list of requests. Optionally filter by date and status.",
        manual_parameters=[
            openapi.Parameter('date', openapi.IN_QUERY, description="Filter requests after a specific date", type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
            openapi.Parameter('status', openapi.IN_QUERY, description="Filter requests by status", type=openapi.TYPE_STRING)
        ],
        responses={200: RequestSerializer(many=True)}
    )

    def get(self, request):
        if request.user.is_staff:
            if 'date' in request.GET and 'status' in request.GET:
                requests = Request.objects.filter(formed_at__gte=request.GET['date'],status=request.GET['status']).exclude(formed_at=None).exclude(status='draft')
            else:
                requests = Request.objects.exclude(status='draft')
        else:
            if 'date' in request.GET and 'status' in request.GET:
                requests = Request.objects.filter(formed_at__gte=request.GET['date'],status=request.GET['status'],user=request.user).exclude(status='deleted')
            else:
                requests = Request.objects.filter(user=request.user).exclude(status='deleted')

        
        req_serializer = RequestSerializer(requests,many=True)
        return Response(req_serializer.data,status=status.HTTP_200_OK)

class GetRequests(APIView):
    
    @swagger_auto_schema(
        operation_description="Get details of a request by ID, including associated threats.",
        responses={200: RequestSerializer()}
    )
    def get(self, request, pk):
        if Request.objects.filter(pk=pk).exclude(status='deleted').exists():
            req = Request.objects.get(pk=pk)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = RequestSerializer(req)

        threat_requests = RequestThreat.objects.filter(request=req)
        threats_ids = []
        for threat_request in threat_requests:
            threats_ids.append(threat_request.threat_id)

        threats_in_request = []
        for id in threats_ids:
            threats_in_request.append(get_object_or_404(Threat,pk=id))

        threats_serializer = ThreatListInRequestSerializer(threats_in_request,many=True,context={'req_id':pk})
        response = serializer.data
        response['threats'] = threats_serializer.data

        return Response(response,status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="Update a request by ID.",
        request_body=PutRequestSerializer,
        responses={200: "Request updated successfully", 400: "Bad request"}
    )
    def put(self, request, pk):
        serializer = PutRequestSerializer(data=request.data)
        if serializer.is_valid():
            req = get_object_or_404(Request, pk=pk)
            for attr, value in serializer.validated_data.items():
                setattr(req, attr, value)
            req.save()
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class FormRequests(APIView):

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Mark a request as formed. Only available for requests with a 'draft' status.",
        responses={200: "Request successfully formed", 400: "Bad request"}
    )
    def put(self, request, pk):
        req = get_object_or_404(Request, pk=pk)
        if not req.status=='draft':
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
        # authorization check
        if not request.user == req.user:
            return Response(status=status.HTTP_403_FORBIDDEN)
        
        if req.created_at > datetime.now():
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if not req.ended_at == None:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
        req.formed_at = datetime.now()
        req.status = 'formed'
        req.save()
        return Response(status=status.HTTP_200_OK)
    

class ModerateRequests(APIView):
    @swagger_auto_schema(
        operation_description="Approve or decline a request (for moderators).",
        request_body=AcceptRequestSerializer,
        responses={200: "Request moderated successfully", 400: "Bad request"}
    )
    def put(self,request,pk):

        if not request.user.is_staff:
            return Response(status=status.HTTP_403_FORBIDDEN)

        req = get_object_or_404(Request, pk=pk)
        serializer = AcceptRequestSerializer(data=request.data)
        if not req.status == 'formed':
            return Response({'error':'Заявка не сформирована'},status=status.HTTP_400_BAD_REQUEST)
        if serializer.is_valid():
            if serializer.validated_data['accept'] == True and req.status:
                req.status = 'ended'
                req.moderator = request.user

                # calc final price
                threat_requests = RequestThreat.objects.filter(request=req)

                final_price = 0

                for threat_request in threat_requests:
                    if threat_request.price != None:
                        final_price = final_price + threat_request.price

                req.final_price = final_price
            else:
                req.status = 'declined'
                req.moderator = request.user 
                req.ended_at = datetime.now()
            req.save()
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        

    @swagger_auto_schema(
        operation_description="Delete a request (for moderators).",
        responses={200: "Request deleted successfully"}
    )
    def delete(self, request, pk):
        req = get_object_or_404(Request, pk=pk)

        # TODO auth
        #if not request.user.is_staff or not request.user == Request:
        #    return Response(status=status.HTTP_403_FORBIDDEN)
        
        req.status = 'deleted'
        req.formed_at = datetime.now()
        req.save()
        return Response(status=status.HTTP_200_OK)
    

class EditRequestThreat(APIView):
    
    @swagger_auto_schema(
        operation_description="Remove a threat from a request.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={'threat_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID of the threat")},
            required=['threat_id']
        ),
        responses={200: "Threat removed successfully", 400: "Bad request"}
    )
    def delete(self, request, pk):
        if 'threat_id' in request.data:
            record = get_object_or_404(RequestThreat, request=pk,threat=request.data['threat_id'])
            record.delete()
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
    @swagger_auto_schema(
        operation_description="Update the price of a threat in a request.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'threat_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID of the threat"),
                'price': openapi.Schema(type=openapi.TYPE_NUMBER, description="New price of the threat")
            },
            required=['threat_id', 'price']
        ),
        responses={200: "Price updated successfully", 400: "Bad request"}
    )
    def put(self,request,pk):
        if not request.user.is_staff:
            return Response(status=status.HTTP_403_FORBIDDEN)
        if 'threat_id' in request.data and 'price' in request.data:
            record = get_object_or_404(RequestThreat, request=pk,threat=request.data['threat_id'])
            record.price = request.data['price']
            record.save()
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)
