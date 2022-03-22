from django.contrib.auth import login
from django.contrib.auth.models import User

from rest_framework import generics, permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import permissions
from rest_framework.authtoken.serializers import AuthTokenSerializer

from knox.views import LoginView as KnoxLoginView
from knox.models import AuthToken

import jwt
import datetime

from .models import Task
from .serializers import TaskSerializer, UserSerializer, RegisterSerializer


@api_view(['GET'])
def getRoutes(request):

    routes = [
        {'GET': '/get-task'},
        {'GET': '/view-task/<str:pk>'},
        {'POST': '/add-task'},
        {'POST': '/update-task/<str:pk>'},
        {'DELETE': '/delete-task/<str:pk>'},
        {'POST': '/register'},
        {'POST': '/login'},
        {'POST': '/logout'},
        {'POST': '/token'},
        {'POST': '/token/refresh'},
    ]
    return Response(routes)


@api_view(['GET'])
def getTask(request, pk):
    # token = request.META.get('HTTP_AUTHORIZATION')
    # if not token:
    #     return Response(status=status.HTTP_401_UNAUTHORIZED)
    # token = token.split(' ')[1]

    # payload = jwt.decode(token, 'secret', algorithms='HS256')

    tasks = Task.objects.filter(owner=pk)
    serializer = TaskSerializer(tasks, many=True)
    return Response(serializer.data)


@api_view(['POST'])
def addTask(request):
    serializer = TaskSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
    return Response(serializer.data)


@api_view(['DELETE'])
def deleteTask(request, pk):
    task = Task.objects.get(id=pk)
    task.delete()
    return Response({
        'success': True,
        'message': 'Task deleted'
    })

# update task status


@api_view(['POST'])
def updateTask(request, pk):
    task = Task.objects.get(id=pk)
    serializer = TaskSerializer(instance=task, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response({
            "success": True,
            "task": serializer.data
        })
    else:
        return Response({
            'success': False,
            'error': serializer.errors
        })


@api_view(['GET'])
def viewTask(request, pk):
    task = Task.objects.get(id=pk)
    serializer = TaskSerializer(instance=task)
    return Response({
        "success": True,
        'task': serializer.data
    })


class RegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        data = request.data

        serializer = self.get_serializer(data=data)

        if User.objects.filter(email=data['email']).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            user = serializer.save()
            payload = {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
            token = jwt.encode(payload, 'secret', algorithm='HS256')
            return Response({
                'user': token,
                'success': True
            })

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow(),
            'username': user.username,
            'email': user.email
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        return Response({
            'user': token,
            'success': True
        })
