from django.urls import path
from knox import views as knox_views
from rest_framework_simplejwt import views as jwt_views
from . import views
from .views import RegisterAPI, LoginAPI, getRoutes

urlpatterns = [
    path('', views.getRoutes),
    path('get-task/<str:pk>', views.getTask),
    path('add-task/', views.addTask),
    path('update-task/<str:pk>', views.updateTask),
    path('view-task/<str:pk>', views.viewTask),
    path('delete-task/<str:pk>', views.deleteTask),
    path('register/', RegisterAPI.as_view(), name='register'),
    path('login/', LoginAPI.as_view(), name='login'),
    path('logout/', knox_views.LogoutView.as_view(), name='logout'),
    path('logoutall/', knox_views.LogoutAllView.as_view(), name='logoutall'),
    path('token/', jwt_views.TokenObtainPairView.as_view(),
         name='token_obtain_pair'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
]
