from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class PostModel(models.Model):
	owner		= models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
	Nama		= models.TextField()
	Password	= models.TextField()
	NIK         = models.TextField()
	image 		= models.CharField(max_length=255, blank=True, default='default.png', null=True)
	image_ciphertext = models.TextField(blank=True, default='')
	Alamat		= models.TextField()
	aes_key		= models.TextField(blank=True, default='')
	key_salt	= models.CharField(max_length=64, blank=True, default='')

	published	= models.DateTimeField(auto_now_add = True)
	updated		= models.DateTimeField(auto_now = True)

	def __str__(self):
		return "{}. {}".format(self.id, self.Nama)
