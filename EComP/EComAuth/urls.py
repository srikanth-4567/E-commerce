from django.urls import path
from EComAuth import views

urlpatterns = [
    path('signup/',views.signup,name='signup'),
    path('login/',views.Login,name='login'),
    path('logout/',views.Logout,name='logout'),
    path('activate/<uidb64>/<token>',views.activate,name='activate'),
    path('request-reset-email/',views.RequestResetEmailView.as_view(),name='request-resete-mail'),
    # when we use as_view create class
    path('set-new-password/<uidb64>/<token>',views.SetNewPasswordView.as_view(),name='set-new-password')
]