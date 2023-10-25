from django.urls import path
from EComApp import views

urlpatterns = [
    path('',views.home,name='home'),
    path('purchase',views.purchase,name='purchase'),
    path('checkout',views.checkout,name='checkout')
]