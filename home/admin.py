from django.contrib import admin

from home.models import Contact
from home.models import Fileadmin

# Register your models here.
admin.site.register(Contact)
admin.site.register(Fileadmin)