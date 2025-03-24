from django.contrib.auth import get_user_model
from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from users.serializers import UserSerializer, RegisterSerializer, ProfileSerializer
from rest_framework import permissions
from users.permissions import IsObjectOwnerOrReadOnly

User = get_user_model()

class RegisterViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

class UserViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

class IsOwnerOrReadOnly(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        
        return obj == request.user

class ProfileViewSet(viewsets.GenericViewSet, mixins.RetrieveModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated, IsObjectOwnerOrReadOnly]

    def get_object(self):
        return self.request.user

    @action(detail=False, methods=['get', 'put', 'patch', 'delete'], permission_classes=[IsAuthenticated, IsObjectOwnerOrReadOnly])
    def me(self, request):
        user = self.get_object()

        if request.method == 'GET':
            serializer = self.get_serializer(user)
            return Response(serializer.data)

        serializer = self.get_serializer(user, data=request.data, partial=request.method == 'PATCH')
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        if request.method == 'DELETE':
            user.delete()
            return Response(status=204)

        return Response(serializer.errors, status=400)