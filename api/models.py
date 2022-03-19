from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class Task(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=200)
    created = models.DateTimeField(auto_now_add=True)
    completed = models.BooleanField(default=False, null=True, blank=True)


    def __str__(self):
        return self.title

    class Meta:
        ordering = ['completed']