from django.db import models

# Create your models here.
class Contact(models.Model):
    name = models.CharField(max_length=122)
    email = models.CharField(max_length=122)
    phone = models.CharField(max_length=12)
    desc = models.TextField()
    date = models.DateField()

    def __str__(self):
        return self.email
class Fileadmin(models.Model):
    adminupload=models.FileField(upload_to='media')
    title=models.CharField(max_length=50)
    def __str__(self):
        return self.title